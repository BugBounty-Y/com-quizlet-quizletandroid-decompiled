package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;

/* loaded from: classes.dex */
public class ThreadGroupDeserializer extends StdNodeBasedDeserializer<ThreadGroup> {
    public ThreadGroupDeserializer() {
        super(ThreadGroup.class);
    }

    @Override // com.fasterxml.jackson.databind.deser.std.StdNodeBasedDeserializer
    public ThreadGroup convert(JsonNode jsonNode, DeserializationContext deserializationContext) throws IOException {
        String strAsText = jsonNode.path("name").asText();
        if (strAsText == null) {
            strAsText = "";
        }
        return new ThreadGroup(strAsText);
    }
}
