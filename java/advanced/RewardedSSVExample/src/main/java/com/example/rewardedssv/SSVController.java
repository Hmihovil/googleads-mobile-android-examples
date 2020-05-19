package com.example.rewardedssv;

import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
/** SSV REST Controller */
@RestController
public class SSVController {
  private static final String SIGNATURE_PARAM_KEY = "signature";
  private static final String KEY_ID_PARAM_KEY = "key_id";
  private static final String REWARD_VERIFIER_KEYS_URL =
      "https://www.gstatic.com/admob/reward/verifier-keys.json";

  private static Map<Long, ECPublicKey> parsePublicKeysJson()
      throws GeneralSecurityException, IOException, JSONException {
    URL url = new URL(REWARD_VERIFIER_KEYS_URL);
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod("GET");
    BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
    String inputLine;
    StringBuffer content = new StringBuffer();
    while ((inputLine = reader.readLine()) != null) {
      content.append(inputLine);
    }
    reader.close();
    connection.disconnect();
    String publicKeysJson = content.toString();
    JSONArray keys = new JSONObject(publicKeysJson).getJSONArray("keys");
    Map<Long, ECPublicKey> publicKeys = new HashMap<>();
    for (int i = 0; i < keys.length(); i++) {
      JSONObject key = keys.getJSONObject(i);
      publicKeys.put(
          key.getLong("keyId"),
          EllipticCurves.getEcPublicKey(Base64.decode(key.getString("base64"))));
    }
    if (publicKeys.isEmpty()) {
      throw new GeneralSecurityException("No trusted keys are available for this protocol version");
    }
    return publicKeys;
  }

  private static String urlEncode(Map<String, String[]> map) {
    StringBuilder stringBuilder = new StringBuilder();
    for (Map.Entry<String, String[]> entry : map.entrySet()) {
      String key = entry.getKey();
      if (!key.equals(SIGNATURE_PARAM_KEY) && !key.equals(KEY_ID_PARAM_KEY)) {
        if (stringBuilder.length() > 0) {
          stringBuilder.append("&");
        }
        String[] values = (String[]) entry.getValue();
        stringBuilder.append(String.format("%s=%s", key, values[0]));
      }
    }
    return stringBuilder.toString();
  }

  private void verify(final byte[] dataToVerify, Long keyId, final byte[] signature)
      throws GeneralSecurityException {
    try {
      Map<Long, ECPublicKey> publicKeys = parsePublicKeysJson();
      if (publicKeys.containsKey(keyId)) {
        ECPublicKey publicKey = publicKeys.get(keyId);
        EcdsaVerifyJce verifier = new EcdsaVerifyJce(publicKey, HashType.SHA256, EcdsaEncoding.DER);
        verifier.verify(signature, dataToVerify);
      } else {
        throw new GeneralSecurityException(
            String.format("Cannot find verifying key with key id: %s.", keyId));
      }
    } catch (JSONException | IOException exception) {
      throw new GeneralSecurityException(exception);
    }
  }

  @GetMapping(value = "/verify")
  public ResponseEntity<?> index(HttpServletRequest request) {

    Enumeration enumeration = request.getParameterNames();
    Map<String, String[]> parameters = request.getParameterMap();

    Map<String, String> response = new HashMap<>();
    response.put("verified", Boolean.FALSE.toString());
    if (parameters.containsKey(KEY_ID_PARAM_KEY) && parameters.containsKey(SIGNATURE_PARAM_KEY)) {
      Long keyId = Long.valueOf(parameters.get(KEY_ID_PARAM_KEY)[0]);
      String signature = parameters.get(SIGNATURE_PARAM_KEY)[0];

      byte[] payLoad = urlEncode(parameters).getBytes(Charset.forName("UTF-8"));
      try {
        verify(payLoad, keyId, Base64.urlSafeDecode(signature));
        response.put("payload", new String(payLoad));
        response.put("key_id", keyId.toString());
        response.put("sig", signature);
        response.put("verified", Boolean.TRUE.toString());
        return new ResponseEntity<>(response, HttpStatus.OK);
      } catch (GeneralSecurityException exception) {
        response.put("error", exception.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
      }
    }
    response.put("error", "Missing key_id and/or signature parameters.");
    return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
  }
}
