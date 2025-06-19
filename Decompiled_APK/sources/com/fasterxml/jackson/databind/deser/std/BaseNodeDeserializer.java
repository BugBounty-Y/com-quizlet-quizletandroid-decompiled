package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadCapability;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.cfg.DatatypeFeatures;
import com.fasterxml.jackson.databind.cfg.JsonNodeFeature;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ContainerNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.type.LogicalType;
import com.fasterxml.jackson.databind.util.RawValue;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;

/* loaded from: classes.dex */
abstract class BaseNodeDeserializer<T extends JsonNode> extends StdDeserializer<T> implements ContextualDeserializer {
    protected final boolean _mergeArrays;
    protected final boolean _mergeObjects;
    protected final Boolean _supportsUpdates;

    public static final class ContainerStack {
        private int _end;
        private ContainerNode[] _stack;
        private int _top;

        public ContainerNode popOrNull() {
            int i = this._top;
            if (i == 0) {
                return null;
            }
            ContainerNode[] containerNodeArr = this._stack;
            int i2 = i - 1;
            this._top = i2;
            return containerNodeArr[i2];
        }

        public void push(ContainerNode containerNode) {
            int i = this._top;
            int i2 = this._end;
            if (i < i2) {
                ContainerNode[] containerNodeArr = this._stack;
                this._top = i + 1;
                containerNodeArr[i] = containerNode;
                return;
            }
            if (this._stack == null) {
                this._end = 10;
                this._stack = new ContainerNode[10];
            } else {
                int iMin = Math.min(4000, Math.max(20, i2 >> 1)) + i2;
                this._end = iMin;
                this._stack = (ContainerNode[]) Arrays.copyOf(this._stack, iMin);
            }
            ContainerNode[] containerNodeArr2 = this._stack;
            int i3 = this._top;
            this._top = i3 + 1;
            containerNodeArr2[i3] = containerNode;
        }
    }

    public BaseNodeDeserializer(Class<T> cls, Boolean bool) {
        super((Class<?>) cls);
        this._supportsUpdates = bool;
        this._mergeArrays = true;
        this._mergeObjects = true;
    }

    private static boolean _shouldMerge(Boolean bool, Boolean bool2) {
        if (bool != null) {
            return bool.booleanValue();
        }
        if (bool2 != null) {
            return bool2.booleanValue();
        }
        return true;
    }

    public abstract JsonDeserializer<?> _createWithMerge(boolean z, boolean z2);

    public final JsonNode _deserializeAnyScalar(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        JsonNodeFactory nodeFactory = deserializationContext.getNodeFactory();
        int iCurrentTokenId = jsonParser.currentTokenId();
        if (iCurrentTokenId == 2) {
            return nodeFactory.objectNode();
        }
        switch (iCurrentTokenId) {
            case 6:
                return nodeFactory.textNode(jsonParser.getText());
            case 7:
                return _fromInt(jsonParser, deserializationContext, nodeFactory);
            case 8:
                return _fromFloat(jsonParser, deserializationContext, nodeFactory);
            case 9:
                return nodeFactory.booleanNode(true);
            case 10:
                return nodeFactory.booleanNode(false);
            case 11:
                return nodeFactory.nullNode();
            case 12:
                return _fromEmbedded(jsonParser, deserializationContext);
            default:
                return (JsonNode) deserializationContext.handleUnexpectedToken(handledType(), jsonParser);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x006b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.fasterxml.jackson.databind.node.ContainerNode<?> _deserializeContainerNoRecursion(com.fasterxml.jackson.core.JsonParser r14, com.fasterxml.jackson.databind.DeserializationContext r15, com.fasterxml.jackson.databind.node.JsonNodeFactory r16, com.fasterxml.jackson.databind.deser.std.BaseNodeDeserializer.ContainerStack r17, com.fasterxml.jackson.databind.node.ContainerNode<?> r18) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 324
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.std.BaseNodeDeserializer._deserializeContainerNoRecursion(com.fasterxml.jackson.core.JsonParser, com.fasterxml.jackson.databind.DeserializationContext, com.fasterxml.jackson.databind.node.JsonNodeFactory, com.fasterxml.jackson.databind.deser.std.BaseNodeDeserializer$ContainerStack, com.fasterxml.jackson.databind.node.ContainerNode):com.fasterxml.jackson.databind.node.ContainerNode");
    }

    public final ObjectNode _deserializeObjectAtName(JsonParser jsonParser, DeserializationContext deserializationContext, JsonNodeFactory jsonNodeFactory, ContainerStack containerStack) throws IOException {
        ObjectNode objectNode = jsonNodeFactory.objectNode();
        String strCurrentName = jsonParser.currentName();
        while (strCurrentName != null) {
            JsonToken jsonTokenNextToken = jsonParser.nextToken();
            if (jsonTokenNextToken == null) {
                jsonTokenNextToken = JsonToken.NOT_AVAILABLE;
            }
            int iId = jsonTokenNextToken.id();
            JsonNode jsonNode_deserializeAnyScalar = iId != 1 ? iId != 3 ? _deserializeAnyScalar(jsonParser, deserializationContext) : _deserializeContainerNoRecursion(jsonParser, deserializationContext, jsonNodeFactory, containerStack, jsonNodeFactory.arrayNode()) : _deserializeContainerNoRecursion(jsonParser, deserializationContext, jsonNodeFactory, containerStack, jsonNodeFactory.objectNode());
            JsonNode jsonNodeReplace = objectNode.replace(strCurrentName, jsonNode_deserializeAnyScalar);
            if (jsonNodeReplace != null) {
                _handleDuplicateField(jsonParser, deserializationContext, jsonNodeFactory, strCurrentName, objectNode, jsonNodeReplace, jsonNode_deserializeAnyScalar);
            }
            strCurrentName = jsonParser.nextFieldName();
        }
        return objectNode;
    }

    public final JsonNode _deserializeRareScalar(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        int iCurrentTokenId = jsonParser.currentTokenId();
        return iCurrentTokenId != 2 ? iCurrentTokenId != 8 ? iCurrentTokenId != 12 ? (JsonNode) deserializationContext.handleUnexpectedToken(handledType(), jsonParser) : _fromEmbedded(jsonParser, deserializationContext) : _fromFloat(jsonParser, deserializationContext, deserializationContext.getNodeFactory()) : deserializationContext.getNodeFactory().objectNode();
    }

    public final JsonNode _fromBigDecimal(DeserializationContext deserializationContext, JsonNodeFactory jsonNodeFactory, BigDecimal bigDecimal) {
        DatatypeFeatures datatypeFeatures = deserializationContext.getDatatypeFeatures();
        JsonNodeFeature jsonNodeFeature = JsonNodeFeature.STRIP_TRAILING_BIGDECIMAL_ZEROES;
        if (datatypeFeatures.isExplicitlySet(jsonNodeFeature) ? datatypeFeatures.isEnabled(jsonNodeFeature) : jsonNodeFactory.willStripTrailingBigDecimalZeroes()) {
            try {
                bigDecimal = bigDecimal.signum() == 0 ? new BigDecimal(BigInteger.ZERO, 0) : bigDecimal.stripTrailingZeros();
            } catch (ArithmeticException unused) {
            }
        }
        return jsonNodeFactory.numberNode(bigDecimal);
    }

    public final JsonNode _fromEmbedded(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        JsonNodeFactory nodeFactory = deserializationContext.getNodeFactory();
        Object embeddedObject = jsonParser.getEmbeddedObject();
        return embeddedObject == null ? nodeFactory.nullNode() : embeddedObject.getClass() == byte[].class ? nodeFactory.binaryNode((byte[]) embeddedObject) : embeddedObject instanceof RawValue ? nodeFactory.rawValueNode((RawValue) embeddedObject) : embeddedObject instanceof JsonNode ? (JsonNode) embeddedObject : nodeFactory.pojoNode(embeddedObject);
    }

    public final JsonNode _fromFloat(JsonParser jsonParser, DeserializationContext deserializationContext, JsonNodeFactory jsonNodeFactory) throws IOException {
        JsonParser.NumberTypeFP numberTypeFP = jsonParser.getNumberTypeFP();
        if (numberTypeFP == JsonParser.NumberTypeFP.BIG_DECIMAL) {
            return _fromBigDecimal(deserializationContext, jsonNodeFactory, jsonParser.getDecimalValue());
        }
        Boolean explicitState = deserializationContext.getDatatypeFeatures().getExplicitState(JsonNodeFeature.USE_BIG_DECIMAL_FOR_FLOATS);
        return explicitState == null ? deserializationContext.isEnabled(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS) : explicitState.booleanValue() ? jsonParser.isNaN() ? deserializationContext.isEnabled(JsonNodeFeature.FAIL_ON_NAN_TO_BIG_DECIMAL_COERCION) ? (JsonNode) deserializationContext.handleWeirdNumberValue(handledType(), Double.valueOf(jsonParser.getDoubleValue()), "Cannot convert NaN into BigDecimal", new Object[0]) : jsonNodeFactory.numberNode(jsonParser.getDoubleValue()) : _fromBigDecimal(deserializationContext, jsonNodeFactory, jsonParser.getDecimalValue()) : numberTypeFP == JsonParser.NumberTypeFP.FLOAT32 ? jsonNodeFactory.numberNode(jsonParser.getFloatValue()) : jsonNodeFactory.numberNode(jsonParser.getDoubleValue());
    }

    public final JsonNode _fromInt(JsonParser jsonParser, int i, JsonNodeFactory jsonNodeFactory) throws IOException {
        if (i != 0) {
            return DeserializationFeature.USE_BIG_INTEGER_FOR_INTS.enabledIn(i) ? jsonNodeFactory.numberNode(jsonParser.getBigIntegerValue()) : jsonNodeFactory.numberNode(jsonParser.getLongValue());
        }
        JsonParser.NumberType numberType = jsonParser.getNumberType();
        return numberType == JsonParser.NumberType.INT ? jsonNodeFactory.numberNode(jsonParser.getIntValue()) : numberType == JsonParser.NumberType.LONG ? jsonNodeFactory.numberNode(jsonParser.getLongValue()) : jsonNodeFactory.numberNode(jsonParser.getBigIntegerValue());
    }

    public void _handleDuplicateField(JsonParser jsonParser, DeserializationContext deserializationContext, JsonNodeFactory jsonNodeFactory, String str, ObjectNode objectNode, JsonNode jsonNode, JsonNode jsonNode2) throws IOException {
        if (deserializationContext.isEnabled(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)) {
            deserializationContext.reportInputMismatch(JsonNode.class, "Duplicate field '%s' for `ObjectNode`: not allowed when `DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY` enabled", str);
        }
        if (deserializationContext.isEnabled(StreamReadCapability.DUPLICATE_PROPERTIES)) {
            if (jsonNode.isArray()) {
                ((ArrayNode) jsonNode).add(jsonNode2);
                objectNode.replace(str, jsonNode);
            } else {
                ArrayNode arrayNode = jsonNodeFactory.arrayNode();
                arrayNode.add(jsonNode);
                arrayNode.add(jsonNode2);
                objectNode.replace(str, arrayNode);
            }
        }
    }

    @Override // com.fasterxml.jackson.databind.deser.ContextualDeserializer
    public JsonDeserializer<?> createContextual(DeserializationContext deserializationContext, BeanProperty beanProperty) throws JsonMappingException {
        DeserializationConfig config = deserializationContext.getConfig();
        Boolean defaultMergeable = config.getDefaultMergeable(ArrayNode.class);
        Boolean defaultMergeable2 = config.getDefaultMergeable(ObjectNode.class);
        Boolean defaultMergeable3 = config.getDefaultMergeable(JsonNode.class);
        boolean z_shouldMerge = _shouldMerge(defaultMergeable, defaultMergeable3);
        boolean z_shouldMerge2 = _shouldMerge(defaultMergeable2, defaultMergeable3);
        return (z_shouldMerge == this._mergeArrays && z_shouldMerge2 == this._mergeObjects) ? this : _createWithMerge(z_shouldMerge, z_shouldMerge2);
    }

    @Override // com.fasterxml.jackson.databind.deser.std.StdDeserializer, com.fasterxml.jackson.databind.JsonDeserializer
    public Object deserializeWithType(JsonParser jsonParser, DeserializationContext deserializationContext, TypeDeserializer typeDeserializer) throws IOException {
        return typeDeserializer.deserializeTypedFromAny(jsonParser, deserializationContext);
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public boolean isCachable() {
        return true;
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public LogicalType logicalType() {
        return LogicalType.Untyped;
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public Boolean supportsUpdate(DeserializationConfig deserializationConfig) {
        return this._supportsUpdates;
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x004b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.fasterxml.jackson.databind.JsonNode updateObject(com.fasterxml.jackson.core.JsonParser r8, com.fasterxml.jackson.databind.DeserializationContext r9, com.fasterxml.jackson.databind.node.ObjectNode r10, com.fasterxml.jackson.databind.deser.std.BaseNodeDeserializer.ContainerStack r11) throws java.io.IOException {
        /*
            r7 = this;
            boolean r0 = r8.isExpectedStartObjectToken()
            if (r0 == 0) goto Lb
            java.lang.String r0 = r8.nextFieldName()
            goto L1e
        Lb:
            com.fasterxml.jackson.core.JsonToken r0 = com.fasterxml.jackson.core.JsonToken.FIELD_NAME
            boolean r0 = r8.hasToken(r0)
            if (r0 != 0) goto L1a
            java.lang.Object r8 = r7.deserialize(r8, r9)
            com.fasterxml.jackson.databind.JsonNode r8 = (com.fasterxml.jackson.databind.JsonNode) r8
            return r8
        L1a:
            java.lang.String r0 = r8.currentName()
        L1e:
            com.fasterxml.jackson.databind.node.JsonNodeFactory r4 = r9.getNodeFactory()
        L22:
            if (r0 == 0) goto Lca
            com.fasterxml.jackson.core.JsonToken r1 = r8.nextToken()
            com.fasterxml.jackson.databind.JsonNode r2 = r10.get(r0)
            if (r2 == 0) goto L4b
            boolean r3 = r2 instanceof com.fasterxml.jackson.databind.node.ObjectNode
            if (r3 == 0) goto L50
            com.fasterxml.jackson.core.JsonToken r3 = com.fasterxml.jackson.core.JsonToken.START_OBJECT
            if (r1 != r3) goto L4b
            boolean r3 = r7._mergeObjects
            if (r3 == 0) goto L4b
            r1 = r2
            com.fasterxml.jackson.databind.node.ObjectNode r1 = (com.fasterxml.jackson.databind.node.ObjectNode) r1
            com.fasterxml.jackson.databind.JsonNode r1 = r7.updateObject(r8, r9, r1, r11)
            if (r1 == r2) goto L46
            r10.set(r0, r1)
        L46:
            r2 = r8
            r3 = r9
            r5 = r11
            goto Lc1
        L4b:
            r2 = r8
            r3 = r9
            r5 = r11
            r8 = r7
            goto L68
        L50:
            boolean r3 = r2 instanceof com.fasterxml.jackson.databind.node.ArrayNode
            if (r3 == 0) goto L4b
            com.fasterxml.jackson.core.JsonToken r3 = com.fasterxml.jackson.core.JsonToken.START_ARRAY
            if (r1 != r3) goto L4b
            boolean r3 = r7._mergeArrays
            if (r3 == 0) goto L4b
            r6 = r2
            com.fasterxml.jackson.databind.node.ArrayNode r6 = (com.fasterxml.jackson.databind.node.ArrayNode) r6
            r1 = r7
            r2 = r8
            r3 = r9
            r5 = r11
            r1._deserializeContainerNoRecursion(r2, r3, r4, r5, r6)
            r8 = r1
            goto Lc1
        L68:
            if (r1 != 0) goto L6c
            com.fasterxml.jackson.core.JsonToken r1 = com.fasterxml.jackson.core.JsonToken.NOT_AVAILABLE
        L6c:
            int r9 = r1.id()
            r11 = 1
            if (r9 == r11) goto Lb5
            r1 = 3
            if (r9 == r1) goto Lab
            r1 = 6
            if (r9 == r1) goto La2
            r1 = 7
            if (r9 == r1) goto L9d
            switch(r9) {
                case 9: goto L98;
                case 10: goto L92;
                case 11: goto L84;
                default: goto L7f;
            }
        L7f:
            com.fasterxml.jackson.databind.JsonNode r9 = r7._deserializeRareScalar(r2, r3)
            goto Lbe
        L84:
            com.fasterxml.jackson.databind.cfg.JsonNodeFeature r9 = com.fasterxml.jackson.databind.cfg.JsonNodeFeature.READ_NULL_PROPERTIES
            boolean r9 = r3.isEnabled(r9)
            if (r9 != 0) goto L8d
            goto Lc1
        L8d:
            com.fasterxml.jackson.databind.node.NullNode r9 = r4.nullNode()
            goto Lbe
        L92:
            r9 = 0
            com.fasterxml.jackson.databind.node.BooleanNode r9 = r4.booleanNode(r9)
            goto Lbe
        L98:
            com.fasterxml.jackson.databind.node.BooleanNode r9 = r4.booleanNode(r11)
            goto Lbe
        L9d:
            com.fasterxml.jackson.databind.JsonNode r9 = r7._fromInt(r2, r3, r4)
            goto Lbe
        La2:
            java.lang.String r9 = r2.getText()
            com.fasterxml.jackson.databind.node.TextNode r9 = r4.textNode(r9)
            goto Lbe
        Lab:
            com.fasterxml.jackson.databind.node.ArrayNode r6 = r4.arrayNode()
            r1 = r8
            com.fasterxml.jackson.databind.node.ContainerNode r9 = r1._deserializeContainerNoRecursion(r2, r3, r4, r5, r6)
            goto Lbe
        Lb5:
            com.fasterxml.jackson.databind.node.ObjectNode r6 = r4.objectNode()
            r1 = r7
            com.fasterxml.jackson.databind.node.ContainerNode r9 = r1._deserializeContainerNoRecursion(r2, r3, r4, r5, r6)
        Lbe:
            r10.set(r0, r9)
        Lc1:
            java.lang.String r0 = r2.nextFieldName()
            r8 = r2
            r9 = r3
            r11 = r5
            goto L22
        Lca:
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.std.BaseNodeDeserializer.updateObject(com.fasterxml.jackson.core.JsonParser, com.fasterxml.jackson.databind.DeserializationContext, com.fasterxml.jackson.databind.node.ObjectNode, com.fasterxml.jackson.databind.deser.std.BaseNodeDeserializer$ContainerStack):com.fasterxml.jackson.databind.JsonNode");
    }

    public BaseNodeDeserializer(BaseNodeDeserializer<?> baseNodeDeserializer, boolean z, boolean z2) {
        super(baseNodeDeserializer);
        this._supportsUpdates = baseNodeDeserializer._supportsUpdates;
        this._mergeArrays = z;
        this._mergeObjects = z2;
    }

    public final JsonNode _fromInt(JsonParser jsonParser, DeserializationContext deserializationContext, JsonNodeFactory jsonNodeFactory) throws IOException {
        JsonParser.NumberType numberType;
        int deserializationFeatures = deserializationContext.getDeserializationFeatures();
        if ((StdDeserializer.F_MASK_INT_COERCIONS & deserializationFeatures) != 0) {
            if (DeserializationFeature.USE_BIG_INTEGER_FOR_INTS.enabledIn(deserializationFeatures)) {
                numberType = JsonParser.NumberType.BIG_INTEGER;
            } else if (DeserializationFeature.USE_LONG_FOR_INTS.enabledIn(deserializationFeatures)) {
                numberType = JsonParser.NumberType.LONG;
            } else {
                numberType = jsonParser.getNumberType();
            }
        } else {
            numberType = jsonParser.getNumberType();
        }
        if (numberType == JsonParser.NumberType.INT) {
            return jsonNodeFactory.numberNode(jsonParser.getIntValue());
        }
        if (numberType == JsonParser.NumberType.LONG) {
            return jsonNodeFactory.numberNode(jsonParser.getLongValue());
        }
        return jsonNodeFactory.numberNode(jsonParser.getBigIntegerValue());
    }
}
