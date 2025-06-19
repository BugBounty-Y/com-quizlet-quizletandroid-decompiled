package com.fasterxml.jackson.core;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.core.exc.InputCoercionException;
import com.fasterxml.jackson.core.util.JacksonFeatureSet;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;

/* loaded from: classes.dex */
public abstract class JsonParser implements Closeable, AutoCloseable {
    protected static final JacksonFeatureSet<StreamReadCapability> DEFAULT_READ_CAPABILITIES = JacksonFeatureSet.fromDefaults(StreamReadCapability.values());
    protected int _features;

    public enum Feature {
        AUTO_CLOSE_SOURCE(true),
        ALLOW_COMMENTS(false),
        ALLOW_YAML_COMMENTS(false),
        ALLOW_UNQUOTED_FIELD_NAMES(false),
        ALLOW_SINGLE_QUOTES(false),
        ALLOW_UNQUOTED_CONTROL_CHARS(false),
        ALLOW_RS_CONTROL_CHAR(false),
        ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER(false),
        ALLOW_NUMERIC_LEADING_ZEROS(false),
        ALLOW_LEADING_PLUS_SIGN_FOR_NUMBERS(false),
        ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS(false),
        ALLOW_TRAILING_DECIMAL_POINT_FOR_NUMBERS(false),
        ALLOW_NON_NUMERIC_NUMBERS(false),
        ALLOW_MISSING_VALUES(false),
        ALLOW_TRAILING_COMMA(false),
        STRICT_DUPLICATE_DETECTION(false),
        IGNORE_UNDEFINED(false),
        INCLUDE_SOURCE_IN_LOCATION(false),
        USE_FAST_DOUBLE_PARSER(false),
        USE_FAST_BIG_NUMBER_PARSER(false);

        private final boolean _defaultState;
        private final int _mask = 1 << ordinal();

        Feature(boolean z) {
            this._defaultState = z;
        }

        public static int collectDefaults() {
            int mask = 0;
            for (Feature feature : values()) {
                if (feature.enabledByDefault()) {
                    mask |= feature.getMask();
                }
            }
            return mask;
        }

        public boolean enabledByDefault() {
            return this._defaultState;
        }

        public boolean enabledIn(int i) {
            return (i & this._mask) != 0;
        }

        public int getMask() {
            return this._mask;
        }
    }

    public enum NumberType {
        INT,
        LONG,
        BIG_INTEGER,
        FLOAT,
        DOUBLE,
        BIG_DECIMAL
    }

    public enum NumberTypeFP {
        FLOAT16,
        FLOAT32,
        DOUBLE64,
        BIG_DECIMAL,
        UNKNOWN
    }

    public JsonParser() {
        this._features = JsonFactory.DEFAULT_PARSER_FEATURE_FLAGS;
    }

    public JsonParseException _constructError(String str) {
        return new JsonParseException(this, str).withRequestPayload(null);
    }

    public JsonParseException _constructReadException(String str) {
        return _constructError(str);
    }

    public void assignCurrentValue(Object obj) {
        JsonStreamContext parsingContext = getParsingContext();
        if (parsingContext != null) {
            parsingContext.setCurrentValue(obj);
        }
    }

    public boolean canParseAsync() {
        return false;
    }

    public boolean canReadObjectId() {
        return false;
    }

    public boolean canReadTypeId() {
        return false;
    }

    public abstract void clearCurrentToken();

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public abstract void close() throws IOException;

    public abstract JsonLocation currentLocation();

    public String currentName() throws IOException {
        return getCurrentName();
    }

    public abstract JsonToken currentToken();

    public abstract int currentTokenId();

    public abstract JsonLocation currentTokenLocation();

    public abstract BigInteger getBigIntegerValue() throws IOException;

    public byte[] getBinaryValue() throws IOException {
        return getBinaryValue(Base64Variants.getDefaultVariant());
    }

    public abstract byte[] getBinaryValue(Base64Variant base64Variant) throws IOException;

    public boolean getBooleanValue() throws IOException {
        JsonToken jsonTokenCurrentToken = currentToken();
        if (jsonTokenCurrentToken == JsonToken.VALUE_TRUE) {
            return true;
        }
        if (jsonTokenCurrentToken == JsonToken.VALUE_FALSE) {
            return false;
        }
        throw new JsonParseException(this, "Current token (" + jsonTokenCurrentToken + ") not of boolean type").withRequestPayload(null);
    }

    public byte getByteValue() throws IOException {
        int intValue = getIntValue();
        if (intValue < -128 || intValue > 255) {
            throw new InputCoercionException(this, a.B("Numeric value (", getText(), ") out of range of Java byte"), JsonToken.VALUE_NUMBER_INT, Byte.TYPE);
        }
        return (byte) intValue;
    }

    public abstract ObjectCodec getCodec();

    @Deprecated
    public abstract String getCurrentName() throws IOException;

    public abstract JsonToken getCurrentToken();

    public abstract BigDecimal getDecimalValue() throws IOException;

    public abstract double getDoubleValue() throws IOException;

    public Object getEmbeddedObject() throws IOException {
        return null;
    }

    public abstract float getFloatValue() throws IOException;

    public abstract int getIntValue() throws IOException;

    public abstract long getLongValue() throws IOException;

    public abstract NumberType getNumberType() throws IOException;

    public abstract NumberTypeFP getNumberTypeFP() throws IOException;

    public abstract Number getNumberValue() throws IOException;

    public Object getNumberValueDeferred() throws IOException {
        return getNumberValue();
    }

    public Object getObjectId() throws IOException {
        return null;
    }

    public abstract JsonStreamContext getParsingContext();

    public abstract JacksonFeatureSet<StreamReadCapability> getReadCapabilities();

    public short getShortValue() throws IOException {
        int intValue = getIntValue();
        if (intValue < -32768 || intValue > 32767) {
            throw new InputCoercionException(this, a.B("Numeric value (", getText(), ") out of range of Java short"), JsonToken.VALUE_NUMBER_INT, Short.TYPE);
        }
        return (short) intValue;
    }

    public abstract String getText() throws IOException;

    public abstract char[] getTextCharacters() throws IOException;

    public abstract int getTextLength() throws IOException;

    public abstract int getTextOffset() throws IOException;

    public Object getTypeId() throws IOException {
        return null;
    }

    public abstract int getValueAsInt() throws IOException;

    public abstract long getValueAsLong() throws IOException;

    public abstract String getValueAsString() throws IOException;

    public abstract boolean hasCurrentToken();

    public abstract boolean hasTextCharacters();

    public abstract boolean hasToken(JsonToken jsonToken);

    public abstract boolean hasTokenId(int i);

    public boolean isEnabled(Feature feature) {
        return feature.enabledIn(this._features);
    }

    public abstract boolean isExpectedNumberIntToken();

    public abstract boolean isExpectedStartArrayToken();

    public abstract boolean isExpectedStartObjectToken();

    public abstract boolean isNaN() throws IOException;

    public String nextFieldName() throws IOException {
        if (nextToken() == JsonToken.FIELD_NAME) {
            return currentName();
        }
        return null;
    }

    public String nextTextValue() throws IOException {
        if (nextToken() == JsonToken.VALUE_STRING) {
            return getText();
        }
        return null;
    }

    public abstract JsonToken nextToken() throws IOException;

    public JsonParser overrideFormatFeatures(int i, int i2) {
        return this;
    }

    public JsonParser overrideStdFeatures(int i, int i2) {
        return setFeatureMask((i & i2) | (this._features & (~i2)));
    }

    public abstract int readBinaryValue(Base64Variant base64Variant, OutputStream outputStream) throws IOException;

    public boolean requiresCustomCodec() {
        return false;
    }

    @Deprecated
    public JsonParser setFeatureMask(int i) {
        this._features = i;
        return this;
    }

    public void setSchema(FormatSchema formatSchema) {
        throw new UnsupportedOperationException("Parser of type " + getClass().getName() + " does not support schema of type '" + formatSchema.getSchemaType() + "'");
    }

    public abstract JsonParser skipChildren() throws IOException;

    public abstract StreamReadConstraints streamReadConstraints();

    public JsonParseException _constructReadException(String str, Object obj) {
        return _constructReadException(String.format(str, obj));
    }

    public boolean isEnabled(StreamReadFeature streamReadFeature) {
        return streamReadFeature.mappedFeature().enabledIn(this._features);
    }

    public JsonParser(int i) {
        this._features = i;
    }

    public JsonParseException _constructReadException(String str, Object obj, Object obj2) {
        return _constructReadException(String.format(str, obj, obj2));
    }

    public JsonParseException _constructReadException(String str, Throwable th) {
        return new JsonParseException(this, str, th);
    }

    public JsonParseException _constructReadException(String str, JsonLocation jsonLocation) {
        return new JsonParseException(this, str, jsonLocation);
    }
}
