package com.fasterxml.jackson.core;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.io.ContentReference;
import com.fasterxml.jackson.core.io.IOContext;
import com.fasterxml.jackson.core.io.SerializedString;
import com.fasterxml.jackson.core.io.UTF8Writer;
import com.fasterxml.jackson.core.json.ByteSourceJsonBootstrapper;
import com.fasterxml.jackson.core.json.ReaderBasedJsonParser;
import com.fasterxml.jackson.core.json.UTF8JsonGenerator;
import com.fasterxml.jackson.core.json.WriterBasedJsonGenerator;
import com.fasterxml.jackson.core.sym.ByteQuadsCanonicalizer;
import com.fasterxml.jackson.core.sym.CharsToNameCanonicalizer;
import com.fasterxml.jackson.core.util.BufferRecycler;
import com.fasterxml.jackson.core.util.JacksonFeature;
import com.fasterxml.jackson.core.util.JsonRecyclerPools;
import com.fasterxml.jackson.core.util.RecyclerPool;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Serializable;
import java.io.StringReader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/* loaded from: classes.dex */
public class JsonFactory extends TokenStreamFactory implements Serializable {
    protected final transient ByteQuadsCanonicalizer _byteSymbolCanonicalizer;
    protected ErrorReportConfiguration _errorReportConfiguration;
    protected int _factoryFeatures;
    protected final List<Object> _generatorDecorators;
    protected int _generatorFeatures;
    protected int _maximumNonEscapedChar;
    protected ObjectCodec _objectCodec;
    protected int _parserFeatures;
    protected final char _quoteChar;
    protected RecyclerPool<BufferRecycler> _recyclerPool;
    protected transient CharsToNameCanonicalizer _rootCharSymbols;
    protected SerializableString _rootValueSeparator;
    protected StreamReadConstraints _streamReadConstraints;
    protected StreamWriteConstraints _streamWriteConstraints;
    protected static final int DEFAULT_FACTORY_FEATURE_FLAGS = Feature.collectDefaults();
    protected static final int DEFAULT_PARSER_FEATURE_FLAGS = JsonParser.Feature.collectDefaults();
    protected static final int DEFAULT_GENERATOR_FEATURE_FLAGS = JsonGenerator.Feature.collectDefaults();
    public static final SerializableString DEFAULT_ROOT_VALUE_SEPARATOR = new SerializedString(" ");

    public enum Feature implements JacksonFeature {
        INTERN_FIELD_NAMES(true),
        CANONICALIZE_FIELD_NAMES(true),
        FAIL_ON_SYMBOL_HASH_OVERFLOW(true),
        USE_THREAD_LOCAL_FOR_BUFFER_RECYCLING(true),
        CHARSET_DETECTION(true);

        private final boolean _defaultState;

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

        @Override // com.fasterxml.jackson.core.util.JacksonFeature
        public boolean enabledByDefault() {
            return this._defaultState;
        }

        @Override // com.fasterxml.jackson.core.util.JacksonFeature
        public boolean enabledIn(int i) {
            return (i & getMask()) != 0;
        }

        @Override // com.fasterxml.jackson.core.util.JacksonFeature
        public int getMask() {
            return 1 << ordinal();
        }
    }

    public JsonFactory() {
        this(null);
    }

    public static <T> List<T> _copy(List<T> list) {
        return list == null ? list : new ArrayList(list);
    }

    public ContentReference _createContentReference(Object obj) {
        return ContentReference.construct(!canHandleBinaryNatively(), obj, this._errorReportConfiguration);
    }

    public IOContext _createContext(ContentReference contentReference, boolean z) {
        BufferRecycler bufferRecycler = null;
        boolean z2 = false;
        if (contentReference == null) {
            contentReference = ContentReference.unknown();
        } else {
            Object rawContent = contentReference.getRawContent();
            if ((rawContent instanceof BufferRecycler.Gettable) && (bufferRecycler = ((BufferRecycler.Gettable) rawContent).bufferRecycler()) != null) {
                z2 = true;
            }
        }
        ContentReference contentReference2 = contentReference;
        if (bufferRecycler == null) {
            bufferRecycler = _getBufferRecycler();
        }
        IOContext iOContext = new IOContext(this._streamReadConstraints, this._streamWriteConstraints, this._errorReportConfiguration, bufferRecycler, contentReference2, z);
        if (z2) {
            iOContext.markBufferRecyclerReleased();
        }
        return iOContext;
    }

    public JsonGenerator _createGenerator(Writer writer, IOContext iOContext) throws IOException {
        WriterBasedJsonGenerator writerBasedJsonGenerator = new WriterBasedJsonGenerator(iOContext, this._generatorFeatures, this._objectCodec, writer, this._quoteChar);
        int i = this._maximumNonEscapedChar;
        if (i > 0) {
            writerBasedJsonGenerator.setHighestNonEscapedChar(i);
        }
        SerializableString serializableString = this._rootValueSeparator;
        if (serializableString != DEFAULT_ROOT_VALUE_SEPARATOR) {
            writerBasedJsonGenerator.setRootValueSeparator(serializableString);
        }
        return _decorate(writerBasedJsonGenerator);
    }

    public JsonParser _createParser(InputStream inputStream, IOContext iOContext) throws IOException {
        try {
            return new ByteSourceJsonBootstrapper(iOContext, inputStream).constructParser(this._parserFeatures, this._objectCodec, this._byteSymbolCanonicalizer, this._rootCharSymbols, this._factoryFeatures);
        } catch (IOException | RuntimeException e) {
            if (iOContext.isResourceManaged()) {
                try {
                    inputStream.close();
                } catch (Exception e2) {
                    e.addSuppressed(e2);
                }
            }
            iOContext.close();
            throw e;
        }
    }

    public JsonGenerator _createUTF8Generator(OutputStream outputStream, IOContext iOContext) throws IOException {
        UTF8JsonGenerator uTF8JsonGenerator = new UTF8JsonGenerator(iOContext, this._generatorFeatures, this._objectCodec, outputStream, this._quoteChar);
        int i = this._maximumNonEscapedChar;
        if (i > 0) {
            uTF8JsonGenerator.setHighestNonEscapedChar(i);
        }
        SerializableString serializableString = this._rootValueSeparator;
        if (serializableString != DEFAULT_ROOT_VALUE_SEPARATOR) {
            uTF8JsonGenerator.setRootValueSeparator(serializableString);
        }
        return _decorate(uTF8JsonGenerator);
    }

    public Writer _createWriter(OutputStream outputStream, JsonEncoding jsonEncoding, IOContext iOContext) throws IOException {
        return jsonEncoding == JsonEncoding.UTF8 ? new UTF8Writer(iOContext, outputStream) : new OutputStreamWriter(outputStream, jsonEncoding.getJavaName());
    }

    public final InputStream _decorate(InputStream inputStream, IOContext iOContext) throws IOException {
        return inputStream;
    }

    public BufferRecycler _getBufferRecycler() {
        return (BufferRecycler) _getRecyclerPool().acquireAndLinkPooled();
    }

    public RecyclerPool<BufferRecycler> _getRecyclerPool() {
        return !Feature.USE_THREAD_LOCAL_FOR_BUFFER_RECYCLING.enabledIn(this._factoryFeatures) ? JsonRecyclerPools.nonRecyclingPool() : this._recyclerPool;
    }

    public boolean canHandleBinaryNatively() {
        return false;
    }

    public boolean canUseCharArrays() {
        return true;
    }

    public JsonGenerator createGenerator(OutputStream outputStream, JsonEncoding jsonEncoding) throws IOException {
        IOContext iOContext_createContext = _createContext(_createContentReference(outputStream), false);
        iOContext_createContext.setEncoding(jsonEncoding);
        return jsonEncoding == JsonEncoding.UTF8 ? _createUTF8Generator(_decorate(outputStream, iOContext_createContext), iOContext_createContext) : _createGenerator(_decorate(_createWriter(outputStream, jsonEncoding, iOContext_createContext), iOContext_createContext), iOContext_createContext);
    }

    public JsonParser createParser(InputStream inputStream) throws IOException {
        IOContext iOContext_createContext = _createContext(_createContentReference(inputStream), false);
        return _createParser(_decorate(inputStream, iOContext_createContext), iOContext_createContext);
    }

    public ObjectCodec getCodec() {
        return this._objectCodec;
    }

    @Override // com.fasterxml.jackson.core.TokenStreamFactory
    public final int getFactoryFeatures() {
        return this._factoryFeatures;
    }

    public Object readResolve() {
        return new JsonFactory(this, this._objectCodec);
    }

    public boolean requiresPropertyOrdering() {
        return false;
    }

    public JsonFactory setCodec(ObjectCodec objectCodec) {
        this._objectCodec = objectCodec;
        return this;
    }

    @Override // com.fasterxml.jackson.core.TokenStreamFactory
    public StreamReadConstraints streamReadConstraints() {
        return this._streamReadConstraints;
    }

    public JsonFactory(ObjectCodec objectCodec) {
        this._byteSymbolCanonicalizer = ByteQuadsCanonicalizer.createRoot();
        this._factoryFeatures = DEFAULT_FACTORY_FEATURE_FLAGS;
        this._parserFeatures = DEFAULT_PARSER_FEATURE_FLAGS;
        this._generatorFeatures = DEFAULT_GENERATOR_FEATURE_FLAGS;
        this._rootValueSeparator = DEFAULT_ROOT_VALUE_SEPARATOR;
        this._recyclerPool = JsonRecyclerPools.defaultPool();
        this._objectCodec = objectCodec;
        this._quoteChar = '\"';
        this._streamReadConstraints = StreamReadConstraints.defaults();
        this._streamWriteConstraints = StreamWriteConstraints.defaults();
        this._errorReportConfiguration = ErrorReportConfiguration.defaults();
        this._generatorDecorators = null;
        this._rootCharSymbols = CharsToNameCanonicalizer.createRoot(this);
    }

    public final OutputStream _decorate(OutputStream outputStream, IOContext iOContext) throws IOException {
        return outputStream;
    }

    public final Reader _decorate(Reader reader, IOContext iOContext) throws IOException {
        return reader;
    }

    public JsonParser createParser(Reader reader) throws IOException {
        IOContext iOContext_createContext = _createContext(_createContentReference(reader), false);
        return _createParser(_decorate(reader, iOContext_createContext), iOContext_createContext);
    }

    public final Writer _decorate(Writer writer, IOContext iOContext) throws IOException {
        return writer;
    }

    public JsonGenerator _decorate(JsonGenerator jsonGenerator) {
        List<Object> list = this._generatorDecorators;
        if (list != null) {
            Iterator<Object> it2 = list.iterator();
            if (it2.hasNext()) {
                throw a.d(it2);
            }
        }
        return jsonGenerator;
    }

    public JsonParser createParser(byte[] bArr) throws IOException {
        return _createParser(bArr, 0, bArr.length, _createContext(_createContentReference(bArr), true));
    }

    public JsonParser _createParser(Reader reader, IOContext iOContext) throws IOException {
        return new ReaderBasedJsonParser(iOContext, this._parserFeatures, reader, this._objectCodec, this._rootCharSymbols.makeChild());
    }

    public JsonGenerator createGenerator(Writer writer) throws IOException {
        IOContext iOContext_createContext = _createContext(_createContentReference(writer), false);
        return _createGenerator(_decorate(writer, iOContext_createContext), iOContext_createContext);
    }

    public JsonParser createParser(String str) throws IOException {
        int length = str.length();
        if (length <= 32768 && canUseCharArrays()) {
            IOContext iOContext_createContext = _createContext(_createContentReference(str), true);
            char[] cArrAllocTokenBuffer = iOContext_createContext.allocTokenBuffer(length);
            str.getChars(0, length, cArrAllocTokenBuffer, 0);
            return _createParser(cArrAllocTokenBuffer, 0, length, iOContext_createContext, true);
        }
        return createParser(new StringReader(str));
    }

    public JsonParser _createParser(char[] cArr, int i, int i2, IOContext iOContext, boolean z) throws IOException {
        return new ReaderBasedJsonParser(iOContext, this._parserFeatures, null, this._objectCodec, this._rootCharSymbols.makeChild(), cArr, i, i + i2, z);
    }

    public JsonParser _createParser(byte[] bArr, int i, int i2, IOContext iOContext) throws IOException {
        return new ByteSourceJsonBootstrapper(iOContext, bArr, i, i2).constructParser(this._parserFeatures, this._objectCodec, this._byteSymbolCanonicalizer, this._rootCharSymbols, this._factoryFeatures);
    }

    public JsonFactory(JsonFactory jsonFactory, ObjectCodec objectCodec) {
        this._byteSymbolCanonicalizer = ByteQuadsCanonicalizer.createRoot();
        this._factoryFeatures = DEFAULT_FACTORY_FEATURE_FLAGS;
        this._parserFeatures = DEFAULT_PARSER_FEATURE_FLAGS;
        this._generatorFeatures = DEFAULT_GENERATOR_FEATURE_FLAGS;
        this._rootValueSeparator = DEFAULT_ROOT_VALUE_SEPARATOR;
        this._recyclerPool = jsonFactory._recyclerPool;
        this._objectCodec = objectCodec;
        this._factoryFeatures = jsonFactory._factoryFeatures;
        this._parserFeatures = jsonFactory._parserFeatures;
        this._generatorFeatures = jsonFactory._generatorFeatures;
        this._generatorDecorators = _copy(jsonFactory._generatorDecorators);
        StreamReadConstraints streamReadConstraints = jsonFactory._streamReadConstraints;
        Objects.requireNonNull(streamReadConstraints);
        this._streamReadConstraints = streamReadConstraints;
        StreamWriteConstraints streamWriteConstraints = jsonFactory._streamWriteConstraints;
        Objects.requireNonNull(streamWriteConstraints);
        this._streamWriteConstraints = streamWriteConstraints;
        ErrorReportConfiguration errorReportConfiguration = jsonFactory._errorReportConfiguration;
        Objects.requireNonNull(errorReportConfiguration);
        this._errorReportConfiguration = errorReportConfiguration;
        this._rootValueSeparator = jsonFactory._rootValueSeparator;
        this._maximumNonEscapedChar = jsonFactory._maximumNonEscapedChar;
        this._quoteChar = jsonFactory._quoteChar;
        this._rootCharSymbols = CharsToNameCanonicalizer.createRoot(this);
    }
}
