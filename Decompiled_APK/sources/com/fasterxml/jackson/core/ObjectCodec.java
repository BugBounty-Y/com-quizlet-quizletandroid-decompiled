package com.fasterxml.jackson.core;

import java.io.IOException;

/* loaded from: classes.dex */
public abstract class ObjectCodec extends TreeCodec {
    public abstract <T extends TreeNode> T readTree(JsonParser jsonParser) throws IOException;

    public abstract <T> T treeToValue(TreeNode treeNode, Class<T> cls) throws JsonProcessingException;

    public abstract void writeValue(JsonGenerator jsonGenerator, Object obj) throws IOException;
}
