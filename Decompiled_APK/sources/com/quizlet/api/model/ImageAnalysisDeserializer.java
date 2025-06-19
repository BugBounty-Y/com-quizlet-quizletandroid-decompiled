package com.quizlet.api.model;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ImageAnalysisDeserializer extends JsonDeserializer<ImageAnalysis> {
    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    @NotNull
    public ImageAnalysis deserialize(@NotNull JsonParser jsonParser, @NotNull DeserializationContext deserializationContext) throws JsonProcessingException {
        TextAnnotationsList textAnnotationsList;
        Intrinsics.checkNotNullParameter(jsonParser, "jsonParser");
        Intrinsics.checkNotNullParameter(deserializationContext, "deserializationContext");
        JsonNode jsonNode = ((JsonNode) jsonParser.getCodec().readTree(jsonParser)).get("imageAnalysis");
        if (jsonNode instanceof ArrayNode) {
            textAnnotationsList = new TextAnnotationsList(K.a);
        } else {
            Object objTreeToValue = jsonParser.getCodec().treeToValue(jsonNode, TextAnnotationsList.class);
            Intrinsics.e(objTreeToValue, "null cannot be cast to non-null type com.quizlet.api.model.TextAnnotationsList");
            textAnnotationsList = (TextAnnotationsList) objTreeToValue;
        }
        return new ImageAnalysis(textAnnotationsList);
    }
}
