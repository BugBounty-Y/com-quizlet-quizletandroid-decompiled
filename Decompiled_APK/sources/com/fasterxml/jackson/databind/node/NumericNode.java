package com.fasterxml.jackson.databind.node;

/* loaded from: classes.dex */
public abstract class NumericNode extends ValueNode {
    public abstract boolean canConvertToInt();

    public abstract boolean canConvertToLong();

    @Override // com.fasterxml.jackson.databind.JsonNode
    public final JsonNodeType getNodeType() {
        return JsonNodeType.NUMBER;
    }

    public abstract int intValue();

    public boolean isNaN() {
        return false;
    }

    public abstract long longValue();
}
