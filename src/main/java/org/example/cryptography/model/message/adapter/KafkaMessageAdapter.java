package org.example.cryptography.model.message.adapter;


import com.google.gson.*;
import org.example.cryptography.model.message.KafkaMessage;

import java.lang.reflect.Type;
import java.util.Base64;

public class KafkaMessageAdapter implements JsonSerializer<KafkaMessage>, JsonDeserializer<KafkaMessage> {
    @Override
    public JsonElement serialize(KafkaMessage message, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("action", message.action().name());
        if (message.content() instanceof Long) {
            jsonObject.addProperty("content", (Long) message.content());
        } else if (message.content() instanceof byte[]) {
            String base64Content = Base64.getEncoder().encodeToString((byte[]) message.content());
            jsonObject.addProperty("content", base64Content);
        } else {
            jsonObject.add("content", context.serialize(message.content()));
        }
        return jsonObject;
    }

    private boolean isBase64String(String str) {
        try {
            Base64.getDecoder().decode(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public KafkaMessage deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        KafkaMessage.Action action = KafkaMessage.Action.valueOf(jsonObject.get("action").getAsString());
        JsonElement contentElement = jsonObject.get("content");

        Object content;
        if (contentElement.isJsonPrimitive() && contentElement.getAsJsonPrimitive().isNumber()) {
            content = contentElement.getAsLong();
        } else if (contentElement.isJsonPrimitive() && contentElement.getAsJsonPrimitive().isString()) {
            String contentString = contentElement.getAsString();
            if (isBase64String(contentString)) {
                content = Base64.getDecoder().decode(contentString);
            } else {
                content = contentString;
            }
        } else {
            content = context.deserialize(contentElement, Object.class);
        }
        return new KafkaMessage(action, content);
    }
}
