package com.fasterxml.jackson.core.filter;

import com.fasterxml.jackson.core.Base64Variant;
import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonStreamContext;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.filter.TokenFilter;
import com.fasterxml.jackson.core.util.JsonParserDelegate;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;

/* loaded from: classes.dex */
public class FilteringParserDelegate extends JsonParserDelegate {
    protected boolean _allowMultipleMatches;
    protected JsonToken _currToken;
    protected TokenFilterContext _exposedContext;
    protected TokenFilterContext _headContext;
    protected TokenFilter.Inclusion _inclusion;
    protected TokenFilter _itemFilter;
    protected JsonToken _lastClearedToken;
    protected int _matchCount;
    protected TokenFilter rootFilter;

    public FilteringParserDelegate(JsonParser jsonParser, TokenFilter tokenFilter, TokenFilter.Inclusion inclusion, boolean z) throws IllegalArgumentException {
        super(jsonParser);
        _checkAsyncParser(jsonParser);
        initializeFilters(tokenFilter, inclusion, z);
    }

    private static void _checkAsyncParser(JsonParser jsonParser) throws IllegalArgumentException {
        if (jsonParser.canParseAsync()) {
            throw new IllegalArgumentException(jsonParser.getClass().getSimpleName().concat(" is an asynchronous parser (canParseAsync() == true), which requires explicit permission to be used: to allow use, call constructor with `allowNonBlockingParser` passed as `true`"));
        }
    }

    private JsonToken _nextBuffered(TokenFilterContext tokenFilterContext) throws IOException {
        this._exposedContext = tokenFilterContext;
        JsonToken jsonTokenNextTokenToRead = tokenFilterContext.nextTokenToRead();
        if (jsonTokenNextTokenToRead != null) {
            return jsonTokenNextTokenToRead;
        }
        while (tokenFilterContext != this._headContext) {
            tokenFilterContext = this._exposedContext.findChildOf(tokenFilterContext);
            this._exposedContext = tokenFilterContext;
            if (tokenFilterContext == null) {
                throw _constructError("Unexpected problem: chain of filtered context broken");
            }
            JsonToken jsonTokenNextTokenToRead2 = tokenFilterContext.nextTokenToRead();
            if (jsonTokenNextTokenToRead2 != null) {
                return jsonTokenNextTokenToRead2;
            }
        }
        throw _constructError("Internal error: failed to locate expected buffered tokens");
    }

    private final boolean _verifyAllowedMatches() throws IOException {
        int i = this._matchCount;
        if (i != 0 && !this._allowMultipleMatches) {
            return false;
        }
        this._matchCount = i + 1;
        return true;
    }

    private void initializeFilters(TokenFilter tokenFilter, TokenFilter.Inclusion inclusion, boolean z) {
        this.rootFilter = tokenFilter;
        this._itemFilter = tokenFilter;
        this._headContext = TokenFilterContext.createRootContext(tokenFilter);
        this._inclusion = inclusion;
        this._allowMultipleMatches = z;
    }

    public JsonStreamContext _filterContext() {
        TokenFilterContext tokenFilterContext = this._exposedContext;
        return tokenFilterContext != null ? tokenFilterContext : this._headContext;
    }

    public final JsonToken _nextToken2() throws IOException {
        TokenFilter tokenFilterCheckValue;
        JsonToken jsonToken_nextTokenWithBuffering;
        JsonToken jsonToken_nextTokenWithBuffering2;
        JsonToken jsonToken_nextTokenWithBuffering3;
        while (true) {
            JsonToken jsonTokenNextToken = this.delegate.nextToken();
            if (jsonTokenNextToken == null) {
                this._currToken = jsonTokenNextToken;
                return jsonTokenNextToken;
            }
            int iId = jsonTokenNextToken.id();
            if (iId == 1) {
                TokenFilter tokenFilter = this._itemFilter;
                TokenFilter tokenFilter2 = TokenFilter.INCLUDE_ALL;
                if (tokenFilter == tokenFilter2) {
                    this._headContext = this._headContext.createChildObjectContext(tokenFilter, true);
                    this._currToken = jsonTokenNextToken;
                    return jsonTokenNextToken;
                }
                if (tokenFilter == null) {
                    this.delegate.skipChildren();
                } else {
                    TokenFilter tokenFilterCheckValue2 = this._headContext.checkValue(tokenFilter);
                    if (tokenFilterCheckValue2 == null) {
                        this.delegate.skipChildren();
                    } else {
                        if (tokenFilterCheckValue2 != tokenFilter2) {
                            tokenFilterCheckValue2 = tokenFilterCheckValue2.filterStartObject();
                        }
                        this._itemFilter = tokenFilterCheckValue2;
                        if (tokenFilterCheckValue2 == tokenFilter2) {
                            this._headContext = this._headContext.createChildObjectContext(tokenFilterCheckValue2, true);
                            this._currToken = jsonTokenNextToken;
                            return jsonTokenNextToken;
                        }
                        if (tokenFilterCheckValue2 != null && this._inclusion == TokenFilter.Inclusion.INCLUDE_NON_NULL) {
                            this._headContext = this._headContext.createChildObjectContext(tokenFilterCheckValue2, true);
                            this._currToken = jsonTokenNextToken;
                            return jsonTokenNextToken;
                        }
                        TokenFilterContext tokenFilterContextCreateChildObjectContext = this._headContext.createChildObjectContext(tokenFilterCheckValue2, false);
                        this._headContext = tokenFilterContextCreateChildObjectContext;
                        if (this._inclusion == TokenFilter.Inclusion.INCLUDE_ALL_AND_PATH && (jsonToken_nextTokenWithBuffering3 = _nextTokenWithBuffering(tokenFilterContextCreateChildObjectContext)) != null) {
                            this._currToken = jsonToken_nextTokenWithBuffering3;
                            return jsonToken_nextTokenWithBuffering3;
                        }
                    }
                }
            } else if (iId == 2) {
                boolean zIsStartHandled = this._headContext.isStartHandled();
                TokenFilter filter = this._headContext.getFilter();
                if (filter != null && filter != TokenFilter.INCLUDE_ALL) {
                    boolean zIncludeEmptyArray = filter.includeEmptyArray(this._headContext.hasCurrentName());
                    filter.filterFinishObject();
                    if (zIncludeEmptyArray) {
                        return _nextBuffered(this._headContext);
                    }
                }
                TokenFilterContext parent = this._headContext.getParent();
                this._headContext = parent;
                this._itemFilter = parent.getFilter();
                if (zIsStartHandled) {
                    this._currToken = jsonTokenNextToken;
                    return jsonTokenNextToken;
                }
            } else if (iId == 3) {
                TokenFilter tokenFilter3 = this._itemFilter;
                TokenFilter tokenFilter4 = TokenFilter.INCLUDE_ALL;
                if (tokenFilter3 == tokenFilter4) {
                    this._headContext = this._headContext.createChildArrayContext(tokenFilter3, true);
                    this._currToken = jsonTokenNextToken;
                    return jsonTokenNextToken;
                }
                if (tokenFilter3 == null) {
                    this.delegate.skipChildren();
                } else {
                    TokenFilter tokenFilterCheckValue3 = this._headContext.checkValue(tokenFilter3);
                    if (tokenFilterCheckValue3 == null) {
                        this.delegate.skipChildren();
                    } else {
                        if (tokenFilterCheckValue3 != tokenFilter4) {
                            tokenFilterCheckValue3 = tokenFilterCheckValue3.filterStartArray();
                        }
                        this._itemFilter = tokenFilterCheckValue3;
                        if (tokenFilterCheckValue3 == tokenFilter4) {
                            this._headContext = this._headContext.createChildArrayContext(tokenFilterCheckValue3, true);
                            this._currToken = jsonTokenNextToken;
                            return jsonTokenNextToken;
                        }
                        if (tokenFilterCheckValue3 != null && this._inclusion == TokenFilter.Inclusion.INCLUDE_NON_NULL) {
                            this._headContext = this._headContext.createChildArrayContext(tokenFilterCheckValue3, true);
                            this._currToken = jsonTokenNextToken;
                            return jsonTokenNextToken;
                        }
                        TokenFilterContext tokenFilterContextCreateChildArrayContext = this._headContext.createChildArrayContext(tokenFilterCheckValue3, false);
                        this._headContext = tokenFilterContextCreateChildArrayContext;
                        if (this._inclusion == TokenFilter.Inclusion.INCLUDE_ALL_AND_PATH && (jsonToken_nextTokenWithBuffering2 = _nextTokenWithBuffering(tokenFilterContextCreateChildArrayContext)) != null) {
                            this._currToken = jsonToken_nextTokenWithBuffering2;
                            return jsonToken_nextTokenWithBuffering2;
                        }
                    }
                }
            } else if (iId == 4) {
                boolean zIsStartHandled2 = this._headContext.isStartHandled();
                TokenFilter filter2 = this._headContext.getFilter();
                if (filter2 != null && filter2 != TokenFilter.INCLUDE_ALL) {
                    boolean zIncludeEmptyArray2 = filter2.includeEmptyArray(this._headContext.hasCurrentIndex());
                    filter2.filterFinishArray();
                    if (zIncludeEmptyArray2) {
                        return _nextBuffered(this._headContext);
                    }
                }
                TokenFilterContext parent2 = this._headContext.getParent();
                this._headContext = parent2;
                this._itemFilter = parent2.getFilter();
                if (zIsStartHandled2) {
                    this._currToken = jsonTokenNextToken;
                    return jsonTokenNextToken;
                }
            } else if (iId != 5) {
                TokenFilter tokenFilter5 = this._itemFilter;
                TokenFilter tokenFilter6 = TokenFilter.INCLUDE_ALL;
                if (tokenFilter5 == tokenFilter6) {
                    this._currToken = jsonTokenNextToken;
                    return jsonTokenNextToken;
                }
                if (tokenFilter5 != null && ((tokenFilterCheckValue = this._headContext.checkValue(tokenFilter5)) == tokenFilter6 || (tokenFilterCheckValue != null && tokenFilterCheckValue.includeValue(this.delegate)))) {
                    if (_verifyAllowedMatches()) {
                        this._currToken = jsonTokenNextToken;
                        return jsonTokenNextToken;
                    }
                }
            } else {
                String strCurrentName = this.delegate.currentName();
                TokenFilter fieldName = this._headContext.setFieldName(strCurrentName);
                TokenFilter tokenFilter7 = TokenFilter.INCLUDE_ALL;
                if (fieldName == tokenFilter7) {
                    this._itemFilter = fieldName;
                    this._currToken = jsonTokenNextToken;
                    return jsonTokenNextToken;
                }
                if (fieldName == null) {
                    this.delegate.nextToken();
                    this.delegate.skipChildren();
                } else {
                    TokenFilter tokenFilterIncludeProperty = fieldName.includeProperty(strCurrentName);
                    if (tokenFilterIncludeProperty == null) {
                        this.delegate.nextToken();
                        this.delegate.skipChildren();
                    } else {
                        this._itemFilter = tokenFilterIncludeProperty;
                        if (tokenFilterIncludeProperty == tokenFilter7) {
                            if (!_verifyAllowedMatches()) {
                                this.delegate.nextToken();
                                this.delegate.skipChildren();
                            } else if (this._inclusion == TokenFilter.Inclusion.INCLUDE_ALL_AND_PATH) {
                                this._currToken = jsonTokenNextToken;
                                return jsonTokenNextToken;
                            }
                        } else if (this._inclusion != TokenFilter.Inclusion.ONLY_INCLUDE_ALL && (jsonToken_nextTokenWithBuffering = _nextTokenWithBuffering(this._headContext)) != null) {
                            this._currToken = jsonToken_nextTokenWithBuffering;
                            return jsonToken_nextTokenWithBuffering;
                        }
                    }
                }
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:104:0x0171, code lost:
    
        return r0;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.fasterxml.jackson.core.JsonToken _nextTokenWithBuffering(com.fasterxml.jackson.core.filter.TokenFilterContext r7) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 466
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.core.filter.FilteringParserDelegate._nextTokenWithBuffering(com.fasterxml.jackson.core.filter.TokenFilterContext):com.fasterxml.jackson.core.JsonToken");
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public void clearCurrentToken() {
        JsonToken jsonToken = this._currToken;
        if (jsonToken != null) {
            this._lastClearedToken = jsonToken;
            this._currToken = null;
        }
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public JsonLocation currentLocation() {
        return this.delegate.currentLocation();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public String currentName() throws IOException {
        JsonStreamContext jsonStreamContext_filterContext = _filterContext();
        JsonToken jsonToken = this._currToken;
        if (jsonToken != JsonToken.START_OBJECT && jsonToken != JsonToken.START_ARRAY) {
            return jsonStreamContext_filterContext.getCurrentName();
        }
        JsonStreamContext parent = jsonStreamContext_filterContext.getParent();
        if (parent == null) {
            return null;
        }
        return parent.getCurrentName();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public JsonToken currentToken() {
        return this._currToken;
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public final int currentTokenId() {
        JsonToken jsonToken = this._currToken;
        if (jsonToken == null) {
            return 0;
        }
        return jsonToken.id();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public JsonLocation currentTokenLocation() {
        return this.delegate.currentTokenLocation();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public BigInteger getBigIntegerValue() throws IOException {
        return this.delegate.getBigIntegerValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public byte[] getBinaryValue(Base64Variant base64Variant) throws IOException {
        return this.delegate.getBinaryValue(base64Variant);
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public boolean getBooleanValue() throws IOException {
        return this.delegate.getBooleanValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public byte getByteValue() throws IOException {
        return this.delegate.getByteValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    @Deprecated
    public String getCurrentName() throws IOException {
        JsonStreamContext jsonStreamContext_filterContext = _filterContext();
        JsonToken jsonToken = this._currToken;
        if (jsonToken != JsonToken.START_OBJECT && jsonToken != JsonToken.START_ARRAY) {
            return jsonStreamContext_filterContext.getCurrentName();
        }
        JsonStreamContext parent = jsonStreamContext_filterContext.getParent();
        if (parent == null) {
            return null;
        }
        return parent.getCurrentName();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    @Deprecated
    public JsonToken getCurrentToken() {
        return this._currToken;
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public BigDecimal getDecimalValue() throws IOException {
        return this.delegate.getDecimalValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public double getDoubleValue() throws IOException {
        return this.delegate.getDoubleValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public Object getEmbeddedObject() throws IOException {
        return this.delegate.getEmbeddedObject();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public float getFloatValue() throws IOException {
        return this.delegate.getFloatValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public int getIntValue() throws IOException {
        return this.delegate.getIntValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public long getLongValue() throws IOException {
        return this.delegate.getLongValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public JsonParser.NumberType getNumberType() throws IOException {
        return this.delegate.getNumberType();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public Number getNumberValue() throws IOException {
        return this.delegate.getNumberValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public JsonStreamContext getParsingContext() {
        return _filterContext();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public short getShortValue() throws IOException {
        return this.delegate.getShortValue();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public String getText() throws IOException {
        return this._currToken == JsonToken.FIELD_NAME ? currentName() : this.delegate.getText();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public char[] getTextCharacters() throws IOException {
        return this._currToken == JsonToken.FIELD_NAME ? currentName().toCharArray() : this.delegate.getTextCharacters();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public int getTextLength() throws IOException {
        return this._currToken == JsonToken.FIELD_NAME ? currentName().length() : this.delegate.getTextLength();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public int getTextOffset() throws IOException {
        if (this._currToken == JsonToken.FIELD_NAME) {
            return 0;
        }
        return this.delegate.getTextOffset();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public int getValueAsInt() throws IOException {
        return this.delegate.getValueAsInt();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public long getValueAsLong() throws IOException {
        return this.delegate.getValueAsLong();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public String getValueAsString() throws IOException {
        return this._currToken == JsonToken.FIELD_NAME ? currentName() : this.delegate.getValueAsString();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public boolean hasCurrentToken() {
        return this._currToken != null;
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public boolean hasTextCharacters() {
        if (this._currToken == JsonToken.FIELD_NAME) {
            return false;
        }
        return this.delegate.hasTextCharacters();
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public final boolean hasToken(JsonToken jsonToken) {
        return this._currToken == jsonToken;
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public boolean hasTokenId(int i) {
        JsonToken jsonToken = this._currToken;
        return jsonToken == null ? i == 0 : jsonToken.id() == i;
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public boolean isExpectedStartArrayToken() {
        return this._currToken == JsonToken.START_ARRAY;
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public boolean isExpectedStartObjectToken() {
        return this._currToken == JsonToken.START_OBJECT;
    }

    /* JADX WARN: Removed duplicated region for block: B:123:0x01a0  */
    @Override // com.fasterxml.jackson.core.JsonParser
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.fasterxml.jackson.core.JsonToken nextToken() throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 580
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.core.filter.FilteringParserDelegate.nextToken():com.fasterxml.jackson.core.JsonToken");
    }

    @Override // com.fasterxml.jackson.core.util.JsonParserDelegate, com.fasterxml.jackson.core.JsonParser
    public int readBinaryValue(Base64Variant base64Variant, OutputStream outputStream) throws IOException {
        return this.delegate.readBinaryValue(base64Variant, outputStream);
    }

    @Override // com.fasterxml.jackson.core.JsonParser
    public JsonParser skipChildren() throws IOException {
        JsonToken jsonToken = this._currToken;
        if (jsonToken == JsonToken.START_OBJECT || jsonToken == JsonToken.START_ARRAY) {
            int i = 1;
            while (true) {
                JsonToken jsonTokenNextToken = nextToken();
                if (jsonTokenNextToken == null) {
                    break;
                }
                if (!jsonTokenNextToken.isStructStart()) {
                    if (jsonTokenNextToken.isStructEnd() && i - 1 == 0) {
                        break;
                    }
                } else {
                    i++;
                }
            }
        }
        return this;
    }
}
