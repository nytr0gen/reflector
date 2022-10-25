package burp;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Set;

import static burp.Constants.*;

public class CheckReflection {

    public static final int QUOTE_BYTE = 0x22; // double quote char
    private static final Set<String> FILTERED_PARAM_VALUES = Set.of(
        "true", "false", "yes", "no"
    );
    private final int bodyOffset;

    private IExtensionHelpers helpers;
    private IHttpRequestResponse iHttpRequestResponse;
    private Settings settings;
    IBurpExtenderCallbacks callbacks;

    public CheckReflection(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse iHttpRequestResponse,
            IBurpExtenderCallbacks callbacks) {
        this.settings = settings;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.bodyOffset = helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getBodyOffset();
    }

    public List<Map> checkResponse() {
        List<Map> reflectedParams = new ArrayList<>();
        List<IParameter> params = helpers.analyzeRequest(iHttpRequestResponse).getParameters();
        byte[] request = iHttpRequestResponse.getRequest();
        for (IParameter param : params) {
            // skip non-string json params
            byte b = request[param.getValueStart() - 1];
            if (param.getType() == IParameter.PARAM_JSON && b != QUOTE_BYTE) {
                continue;
            }

            Map paramDescription = new HashMap();
            paramDescription.put(NAME, param.getName());
            paramDescription.put(VALUE, param.getValue());
            paramDescription.put(TYPE, param.getType());
            paramDescription.put(VALUE_START, param.getValueStart());
            paramDescription.put(VALUE_END, param.getValueEnd());

            // avoid params with short values
            byte[] paramValueBytes = helpers.urlDecode(param.getValue().getBytes());

            paramDescription.put(MATCHES, new ArrayList<>());
            paramDescription.put(REFLECTED_IN, BODY); // default
            // String paramValue = helpers.bytesToString(paramValueBytes);
            if (paramValueBytes.length > 2) {
                List<int[]> listOfMatches = getMatches(iHttpRequestResponse.getResponse(), paramValueBytes);
                if (!listOfMatches.isEmpty()) {
                    paramDescription.put(MATCHES, listOfMatches);
                    paramDescription.put(REFLECTED_IN, checkWhereReflectionPlaced(listOfMatches));
                }
            }

            reflectedParams.add(paramDescription);
        }

        if (settings.getAggressiveMode() && !reflectedParams.isEmpty()) {
            Aggressive scan = new Aggressive(
                settings,
                helpers,
                iHttpRequestResponse,
                callbacks,
                reflectedParams
            );

            scan.scanReflectedParameters();
        } else if (settings.getCheckContext() && !reflectedParams.isEmpty()) {
            String symbols = "",
                    body = new String(iHttpRequestResponse.getResponse()).substring(this.bodyOffset);
            ArrayList<int[]> payloadIndexes = null;

            // cycle by params
            for (Map param : reflectedParams) {
                payloadIndexes = new ArrayList<>();

                for (int[] indexPair : (ArrayList<int[]>) param.get(MATCHES)) {
                    int[] tmpIndexes = new int[] {
                        indexPair[0] - this.bodyOffset,
                        indexPair[1] - this.bodyOffset
                    };

                    payloadIndexes.add(tmpIndexes);
                }

                ContextAnalyzer contextAnalyzer = new ContextAnalyzer(body.toLowerCase(), payloadIndexes);
                symbols = contextAnalyzer.getIssuesForAllParameters();
                if (symbols.length() > 0) {
                    param.put(VULNERABLE, symbols);
                }
            }
        }

        // heuristic param filters
        reflectedParams.removeIf((paramDescription) -> {
            // no matches and no vulnerable symbols
            if (((ArrayList)paramDescription.get(MATCHES)).isEmpty()
                && paramDescription.get(VULNERABLE) == null
            ) {
                return true;
            }

            // very common values and not vulnerable
            if (FILTERED_PARAM_VALUES.contains(paramDescription.get(VALUE))
                && paramDescription.get(VULNERABLE) == null
            ) {
                return true;
            }

            return false;
        });

        return reflectedParams;
    }

    private String checkWhereReflectionPlaced(List<int[]> listOfMatches) {
        String reflectIn = "";
        for (int[] matches : listOfMatches) {
            if (matches[0] < bodyOffset) { // reflected in headers
                if (reflectIn.equals(BODY)) {
                    return BOTH;
                }

                reflectIn = HEADERS;
            } else { // reflected in body
                if (reflectIn.equals(HEADERS)) {
                    return BOTH;
                }

                reflectIn = BODY;
            }
        }

        return reflectIn;
    }

    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, false, start, response.length);
            if (start == -1) {
                break;
            }
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }
}

class Pair {
    private int[] pair;

    public Pair(int[] pair) {
        this.pair = pair;
    }

    public int getStart() {
        return pair[0];
    }

    public int[] getPair() {
        return pair;
    }
}

class Aggressive {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private List<Map> reflectedParams;
    private IHttpRequestResponse baseRequestResponse;
    private String host;
    private int port;
    private static final String PAYLOAD_GREP = "m@p";
    private static final String PAYLOAD = "%22%27%3c"; // "'<
    private static final String PAYLOAD_HEADER = "%22%27%20"; // "'[space]
    private static final String PAYLOAD_JSON = "\\\"'<";
    private Pattern pattern;
    private Settings settings;

    Aggressive(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse baseRequestResponse,
            IBurpExtenderCallbacks callbacks, List<Map> reflectedParams) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.reflectedParams = reflectedParams;
        this.baseRequestResponse = baseRequestResponse;
        this.host = helpers.analyzeRequest(baseRequestResponse).getUrl().getHost();
        this.port = helpers.analyzeRequest(baseRequestResponse).getUrl().getPort();
        this.pattern = Pattern.compile(PAYLOAD_GREP + "([_%&;\"'<#\\\\0-9a-z ]{1,25}?)" + PAYLOAD_GREP, Pattern.CASE_INSENSITIVE);
        this.settings = settings;
    }

    public List<Map> scanReflectedParameters() {
        String testRequest = "",
                symbols = "";
        for (Map param : reflectedParams) {
            // skip cookie params - might reconsider later
            if ((byte)param.get(TYPE) == IParameter.PARAM_COOKIE) {
                continue;
            }

            testRequest = prepareRequest(param);
            symbols = checkResponse(testRequest);
            if (!symbols.isEmpty()) {
                param.put(VULNERABLE, symbols);
            }
        }

        return reflectedParams;
    }

    public static String prepareReflectedPayload(String value) {
        return value.replaceAll("[^<\"' \\\\]", "")
            .replaceAll("[\\\\]", "");
            // .replaceAll("(\\\\\"|\\\\')", "")
    }

    private String checkResponse(String testRequest) {
        String reflectedPayloadValue = "",
                symbols = "";
        int bodyOffset;
        try {
            IHttpRequestResponse responseObject = this.callbacks.makeHttpRequest(
                    this.baseRequestResponse.getHttpService(),
                    testRequest.getBytes());
            String response = helpers.bytesToString(responseObject.getResponse());

            bodyOffset = helpers.analyzeResponse(responseObject.getResponse()).getBodyOffset();

            Matcher matcher = this.pattern.matcher(response);
            ArrayList<int[]> payloadIndexes = new ArrayList<>();
            while (matcher.find()) {
                payloadIndexes.add(new int[] { matcher.start() - bodyOffset, matcher.end() - bodyOffset });
            }
            matcher = null;

            if (settings.getCheckContext() && bodyOffset != response.length()) {
                ContextAnalyzer contextAnalyzer = new ContextAnalyzer(response.substring(bodyOffset).toLowerCase(),
                        payloadIndexes);
                symbols = contextAnalyzer.getIssuesForAllParameters();
            } else if (bodyOffset != 1) {
                for (int[] indexPair : payloadIndexes) {
                    reflectedPayloadValue = Aggressive.prepareReflectedPayload(
                            response.substring(indexPair[0] + bodyOffset, indexPair[1] + bodyOffset));
                    if (reflectedPayloadValue.length() > 0) {
                        for (String str : reflectedPayloadValue.split("")) {
                            symbols += str + "";
                        }
                    }
                }

                if (!symbols.isEmpty()) {
                    symbols = symbols.replaceAll("<", "&#x3c;")
                        .replaceAll("'", "&#x27;")
                        .replaceAll("\"", "&#x22;")
                        .replaceAll(" ", " [space] ")
                        .replaceAll("\\|\\|", "<strong>|</strong>");
                }
            }
        } catch (Exception e) {
            callbacks.printError(e.getMessage());
            return "";
        }

        return symbols;
    }

    private String prepareRequest(Map param) {
        String payload = PAYLOAD;
        if (param.get(REFLECTED_IN) == HEADERS) {
            payload = PAYLOAD_HEADER;
        } else if (param.get(TYPE).equals(IParameter.PARAM_JSON)) {
            payload = PAYLOAD_JSON;
        }

        String tmpRequest = helpers.bytesToString(baseRequestResponse.getRequest());
        tmpRequest = tmpRequest.substring(0, (int)param.get(VALUE_START))
                + PAYLOAD_GREP + payload + PAYLOAD_GREP
                + tmpRequest.substring((int)param.get(VALUE_END));
        String contentLength = "";
        for (String header : helpers.analyzeRequest(baseRequestResponse).getHeaders()) {
            if (header.toLowerCase().startsWith("content-length: ")) {
                contentLength = header;
                break;
            }
        }

        // send the request if the param is in query / cookie
        if (contentLength.isEmpty()
            || (int) param.get(VALUE_START) < helpers.analyzeRequest(baseRequestResponse).getBodyOffset()
        ) {
            return tmpRequest;
        }

        // update Content-Length for POST params
        int paramLength = (int)param.get(VALUE_END) - (int)param.get(VALUE_START);
        int lengthDiff = (PAYLOAD_GREP + payload + PAYLOAD_GREP).length() - paramLength;
        String contentLengthString = contentLength.split(": ")[1].trim();
        int contentLengthInt = Integer.parseInt(contentLengthString) + lengthDiff;
        int contentLengthIntOffsetStart = tmpRequest.toLowerCase().indexOf("content-length");
        tmpRequest = tmpRequest.substring(0, contentLengthIntOffsetStart + 16) +
            String.valueOf(contentLengthInt) +
            tmpRequest.substring(contentLengthIntOffsetStart + 16 + contentLengthString.length());

        return tmpRequest;
    }
}
