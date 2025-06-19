package com.quizlet.db.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.quizlet.db.data.models.wrappers.RawJsonObject;
import java.io.IOException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class RawJsonDeserializer extends JsonDeserializer<RawJsonObject> {
    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public final RawJsonObject deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        Intrinsics.checkNotNullParameter(jp, "jp");
        Intrinsics.checkNotNullParameter(ctxt, "ctxt");
        TreeNode tree = jp.getCodec().readTree(jp);
        Intrinsics.checkNotNullExpressionValue(tree, "readTree(...)");
        return new RawJsonObject(((JsonNode) tree).toString());
    }
}
