package org.ccil.cowan.tagsoup;

import androidx.browser.customtabs.k;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.IOException;
import java.util.HashMap;
import org.xml.sax.ContentHandler;
import org.xml.sax.DTDHandler;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.XMLReader;
import org.xml.sax.ext.LexicalHandler;
import org.xml.sax.helpers.DefaultHandler;

/* loaded from: classes3.dex */
public final class f extends DefaultHandler implements XMLReader, LexicalHandler {
    public static final char[] D = {'<', '/', '>'};
    public k A;
    public k B;
    public boolean C;
    public ContentHandler a;
    public LexicalHandler b;
    public DTDHandler c;
    public ErrorHandler d;
    public EntityResolver e;
    public d f;
    public g g;
    public e h;
    public boolean i;
    public boolean j;
    public boolean k;
    public boolean l;
    public boolean m;
    public boolean n;
    public boolean o;
    public boolean p;
    public boolean q;
    public HashMap r;
    public k s;
    public String t;
    public boolean u;
    public String v;
    public String w;
    public String x;
    public String y;
    public k z;

    public static String k(String str) {
        int iIndexOf = str.indexOf(58);
        return iIndexOf != -1 ? str.substring(0, iIndexOf) : "";
    }

    public static String q(String str) {
        int length;
        char cCharAt;
        return (str == null || (length = str.length()) == 0 || (cCharAt = str.charAt(0)) != str.charAt(length - 1)) ? str : (cCharAt == '\'' || cCharAt == '\"') ? str.substring(1, str.length() - 1) : str;
    }

    public final void a() {
        String str;
        k kVar = this.s;
        if (kVar == null || (str = this.t) == null) {
            return;
        }
        ((b) kVar.b).c((a) kVar.c, str, null, str);
        this.t = null;
    }

    public final void b(char[] cArr, int i) {
        if (this.s == null || this.t == null) {
            return;
        }
        String str = new String(cArr, 0, i);
        int length = str.length();
        char[] cArr2 = new char[length];
        int i2 = 0;
        int i3 = -1;
        for (int i4 = 0; i4 < length; i4++) {
            char cCharAt = str.charAt(i4);
            int i5 = i2 + 1;
            cArr2[i2] = cCharAt;
            if (cCharAt == '&' && i3 == -1) {
                i2 = i5;
                i3 = i2;
            } else if (i3 == -1 || Character.isLetter(cCharAt) || Character.isDigit(cCharAt) || cCharAt == '#') {
                i2 = i5;
            } else if (cCharAt == ';') {
                int iF = f(cArr2, i3, (i5 - i3) - 1);
                if (iF > 65535) {
                    int i6 = iF - 65536;
                    cArr2[i3 - 1] = (char) ((i6 >> 10) + 55296);
                    cArr2[i3] = (char) ((i6 & 1023) + 56320);
                    i3++;
                } else if (iF != 0) {
                    cArr2[i3 - 1] = (char) iF;
                } else {
                    i3 = i5;
                }
                i2 = i3;
                i3 = -1;
            } else {
                i3 = -1;
                i2 = i5;
            }
        }
        String str2 = new String(cArr2, 0, i2);
        k kVar = this.s;
        ((b) kVar.b).c((a) kVar.c, this.t, null, str2);
        this.t = null;
    }

    public final void c(char[] cArr, int i) throws SAXException, IOException {
        String str;
        k kVar;
        this.s = null;
        if (i != 0) {
            b bVarD = this.f.d(g(cArr, i));
            if (bVarD == null) {
                return;
            } else {
                str = bVarD.a;
            }
        } else {
            str = ((b) this.z.b).a;
        }
        k kVar2 = this.z;
        boolean z = false;
        while (kVar2 != null) {
            b bVar = (b) kVar2.b;
            if (bVar.a.equals(str)) {
                break;
            }
            if ((bVar.f & 4) != 0) {
                z = true;
            }
            kVar2 = (k) kVar2.d;
        }
        if (kVar2 == null || (kVar = (k) kVar2.d) == null || ((k) kVar.d) == null) {
            return;
        }
        if (z) {
            kVar2.a = true;
        } else {
            while (this.z != kVar2) {
                o();
            }
            j();
        }
        while (this.z.a) {
            j();
        }
        n(null);
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void comment(char[] cArr, int i, int i2) {
    }

    public final boolean d(String str, String str2) {
        return (str.equals("") || str2.equals("") || str2.equals(this.f.c)) ? false : true;
    }

    public final void e(char[] cArr, int i) {
        String strG;
        if (this.s == null && (strG = g(cArr, i)) != null) {
            b bVarD = this.f.d(strG);
            if (bVarD == null) {
                if (this.j) {
                    return;
                }
                this.f.b(this.k ? 0 : -1, this.l ? -1 : SubsamplingScaleImageView.TILE_SIZE_AUTO, strG, 0);
                if (!this.l) {
                    d dVar = this.f;
                    dVar.e(strG, dVar.e.a);
                }
                bVarD = this.f.d(strG);
            }
            this.s = new k(bVarD, this.m);
        }
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void endCDATA() {
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void endDTD() {
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void endEntity(String str) {
    }

    public final int f(char[] cArr, int i, int i2) {
        char c;
        if (i2 < 1) {
            return 0;
        }
        if (cArr[i] != '#') {
            Integer num = (Integer) this.f.a.get(new String(cArr, i, i2));
            if (num == null) {
                return 0;
            }
            return num.intValue();
        }
        if (i2 <= 1 || !((c = cArr[i + 1]) == 'x' || c == 'X')) {
            try {
                return Integer.parseInt(new String(cArr, i + 1, i2 - 1), 10);
            } catch (NumberFormatException unused) {
                return 0;
            }
        }
        try {
            return Integer.parseInt(new String(cArr, i + 2, i2 - 2), 16);
        } catch (NumberFormatException unused2) {
            return 0;
        }
    }

    public final String g(char[] cArr, int i) {
        StringBuffer stringBuffer = new StringBuffer(i + 2);
        int i2 = 0;
        boolean z = false;
        boolean z2 = true;
        while (true) {
            int i3 = i - 1;
            if (i <= 0) {
                break;
            }
            char c = cArr[i2];
            if (Character.isLetter(c) || c == '_') {
                stringBuffer.append(c);
            } else if (Character.isDigit(c) || c == '-' || c == '.') {
                if (z2) {
                    stringBuffer.append('_');
                }
                stringBuffer.append(c);
            } else {
                if (c == ':' && !z) {
                    if (z2) {
                        stringBuffer.append('_');
                    }
                    stringBuffer.append(this.n ? '_' : c);
                    z2 = true;
                    z = true;
                }
                i2++;
                i = i3;
            }
            z2 = false;
            i2++;
            i = i3;
        }
        int length = stringBuffer.length();
        if (length == 0 || stringBuffer.charAt(length - 1) == ':') {
            stringBuffer.append('_');
        }
        return stringBuffer.toString().intern();
    }

    @Override // org.xml.sax.XMLReader
    public final ContentHandler getContentHandler() {
        ContentHandler contentHandler = this.a;
        if (contentHandler == this) {
            return null;
        }
        return contentHandler;
    }

    @Override // org.xml.sax.XMLReader
    public final DTDHandler getDTDHandler() {
        DTDHandler dTDHandler = this.c;
        if (dTDHandler == this) {
            return null;
        }
        return dTDHandler;
    }

    @Override // org.xml.sax.XMLReader
    public final EntityResolver getEntityResolver() {
        EntityResolver entityResolver = this.e;
        if (entityResolver == this) {
            return null;
        }
        return entityResolver;
    }

    @Override // org.xml.sax.XMLReader
    public final ErrorHandler getErrorHandler() {
        ErrorHandler errorHandler = this.d;
        if (errorHandler == this) {
            return null;
        }
        return errorHandler;
    }

    @Override // org.xml.sax.XMLReader
    public final boolean getFeature(String str) throws SAXNotRecognizedException {
        Boolean bool = (Boolean) this.r.get(str);
        if (bool != null) {
            return bool.booleanValue();
        }
        StringBuffer stringBuffer = new StringBuffer("Unknown feature ");
        stringBuffer.append(str);
        throw new SAXNotRecognizedException(stringBuffer.toString());
    }

    @Override // org.xml.sax.XMLReader
    public final Object getProperty(String str) throws SAXNotRecognizedException {
        if (str.equals("http://xml.org/sax/properties/lexical-handler")) {
            LexicalHandler lexicalHandler = this.b;
            if (lexicalHandler == this) {
                return null;
            }
            return lexicalHandler;
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/properties/scanner")) {
            return this.g;
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/properties/schema")) {
            return this.f;
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/properties/auto-detector")) {
            return this.h;
        }
        throw new SAXNotRecognizedException("Unknown property ".concat(str));
    }

    public final void h(char[] cArr, int i) {
        if (i == 0) {
            return;
        }
        boolean z = true;
        for (int i2 = 0; i2 < i; i2++) {
            if (!Character.isWhitespace(cArr[i2])) {
                z = false;
            }
        }
        if (!z || this.z.d(this.B)) {
            m(this.B);
            this.a.characters(cArr, 0, i);
        } else if (this.p) {
            this.a.ignorableWhitespace(cArr, 0, i);
        }
    }

    public final void i(char[] cArr, int i) throws SAXException {
        String str;
        if (this.s != null || (str = this.y) == null || "xml".equalsIgnoreCase(str)) {
            return;
        }
        if (i > 0 && cArr[i - 1] == '?') {
            i--;
        }
        this.a.processingInstruction(this.y, new String(cArr, 0, i));
        this.y = null;
    }

    public final void j() throws SAXException {
        k kVar = this.z;
        if (kVar == null) {
            return;
        }
        b bVar = (b) kVar.b;
        String str = bVar.a;
        String str2 = bVar.c;
        String str3 = bVar.b;
        String strK = k(str);
        if (!this.i) {
            str2 = "";
            str3 = "";
        }
        this.a.endElement(str3, str2, str);
        if (d(strK, str3)) {
            this.a.endPrefixMapping(strK);
        }
        a aVar = (a) this.z.c;
        for (int i = aVar.a - 1; i >= 0; i--) {
            String uri = aVar.getURI(i);
            String strK2 = k(aVar.getQName(i));
            if (d(strK2, uri)) {
                this.a.endPrefixMapping(strK2);
            }
        }
        this.z = (k) this.z.d;
    }

    public final void l(k kVar) throws SAXException, IOException {
        b bVar = (b) kVar.b;
        String str = bVar.a;
        String str2 = bVar.c;
        String str3 = bVar.b;
        String strK = k(str);
        a aVar = (a) kVar.c;
        for (int i = aVar.a - 1; i >= 0; i--) {
            String localName = aVar.getLocalName(i);
            if (aVar.getValue(i) == null || localName == null || localName.length() == 0) {
                aVar.b(i);
            }
        }
        if (!this.i) {
            str2 = "";
            str3 = "";
        }
        if (this.C && str2.equalsIgnoreCase(this.x)) {
            try {
                this.e.resolveEntity(this.v, this.w);
            } catch (IOException unused) {
            }
        }
        if (d(strK, str3)) {
            this.a.startPrefixMapping(strK, str3);
        }
        int i2 = aVar.a;
        for (int i3 = 0; i3 < i2; i3++) {
            String uri = aVar.getURI(i3);
            String strK2 = k(aVar.getQName(i3));
            if (d(strK2, uri)) {
                this.a.startPrefixMapping(strK2, uri);
            }
        }
        this.a.startElement(str3, str2, str, aVar);
        kVar.d = this.z;
        this.z = kVar;
        this.C = false;
        if (!this.q || (((b) kVar.b).f & 2) == 0) {
            return;
        }
        ((c) this.g).h = 10;
    }

    public final void m(k kVar) throws SAXException, IOException {
        k kVar2;
        k kVar3;
        b bVar;
        while (true) {
            kVar2 = this.z;
            while (kVar2 != null && !kVar2.d(kVar)) {
                kVar2 = (k) kVar2.d;
            }
            if (kVar2 != null || (bVar = ((b) kVar.b).h) == null) {
                break;
            }
            k kVar4 = new k(bVar, this.m);
            kVar4.d = kVar;
            kVar = kVar4;
        }
        if (kVar2 == null) {
            return;
        }
        while (true) {
            k kVar5 = this.z;
            if (kVar5 == kVar2 || kVar5 == null || (kVar3 = (k) kVar5.d) == null || ((k) kVar3.d) == null) {
                break;
            } else {
                o();
            }
        }
        while (kVar != null) {
            k kVar6 = (k) kVar.d;
            if (!((b) kVar.b).a.equals("<pcdata>")) {
                l(kVar);
            }
            n(kVar6);
            kVar = kVar6;
        }
        this.s = null;
    }

    public final void n(k kVar) throws SAXException, IOException {
        while (true) {
            k kVar2 = this.A;
            if (kVar2 == null || !this.z.d(kVar2)) {
                return;
            }
            if (kVar != null && !this.A.d(kVar)) {
                return;
            }
            k kVar3 = this.A;
            k kVar4 = (k) kVar3.d;
            l(kVar3);
            this.A = kVar4;
        }
    }

    public final void o() throws SAXException {
        k kVar = this.z;
        j();
        if (!this.o || (((b) kVar.b).f & 1) == 0) {
            return;
        }
        a aVar = (a) kVar.c;
        for (int i = aVar.a - 1; i >= 0; i--) {
            if (aVar.getType(i).equals("ID") || aVar.getQName(i).equals("name")) {
                aVar.b(i);
            }
        }
        kVar.d = this.A;
        this.A = kVar;
    }

    public final void p(char[] cArr, int i) throws SAXException, IOException {
        k kVar = this.s;
        if (kVar == null) {
            return;
        }
        m(kVar);
        if (((b) this.z.b).d == 0) {
            c(cArr, i);
        }
    }

    @Override // org.xml.sax.XMLReader
    public final void parse(String str) throws SAXException, IOException {
        parse(new InputSource(str));
    }

    @Override // org.xml.sax.XMLReader
    public final void setContentHandler(ContentHandler contentHandler) {
        if (contentHandler == null) {
            contentHandler = this;
        }
        this.a = contentHandler;
    }

    @Override // org.xml.sax.XMLReader
    public final void setDTDHandler(DTDHandler dTDHandler) {
        if (dTDHandler == null) {
            dTDHandler = this;
        }
        this.c = dTDHandler;
    }

    @Override // org.xml.sax.XMLReader
    public final void setEntityResolver(EntityResolver entityResolver) {
        if (entityResolver == null) {
            entityResolver = this;
        }
        this.e = entityResolver;
    }

    @Override // org.xml.sax.XMLReader
    public final void setErrorHandler(ErrorHandler errorHandler) {
        if (errorHandler == null) {
            errorHandler = this;
        }
        this.d = errorHandler;
    }

    @Override // org.xml.sax.XMLReader
    public final void setFeature(String str, boolean z) throws SAXNotRecognizedException {
        HashMap map = this.r;
        if (((Boolean) map.get(str)) == null) {
            StringBuffer stringBuffer = new StringBuffer("Unknown feature ");
            stringBuffer.append(str);
            throw new SAXNotRecognizedException(stringBuffer.toString());
        }
        if (z) {
            map.put(str, Boolean.TRUE);
        } else {
            map.put(str, Boolean.FALSE);
        }
        if (str.equals("http://xml.org/sax/features/namespaces")) {
            this.i = z;
            return;
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/features/ignore-bogons")) {
            this.j = z;
            return;
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/features/bogons-empty")) {
            this.k = z;
            return;
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/features/root-bogons")) {
            this.l = z;
            return;
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/features/default-attributes")) {
            this.m = z;
            return;
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/features/translate-colons")) {
            this.n = z;
            return;
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/features/restart-elements")) {
            this.o = z;
        } else if (str.equals("http://www.ccil.org/~cowan/tagsoup/features/ignorable-whitespace")) {
            this.p = z;
        } else if (str.equals("http://www.ccil.org/~cowan/tagsoup/features/cdata-elements")) {
            this.q = z;
        }
    }

    @Override // org.xml.sax.XMLReader
    public final void setProperty(String str, Object obj) throws SAXNotRecognizedException, SAXNotSupportedException {
        if (str.equals("http://xml.org/sax/properties/lexical-handler")) {
            if (obj == null) {
                this.b = this;
                return;
            } else {
                if (!(obj instanceof LexicalHandler)) {
                    throw new SAXNotSupportedException("Your lexical handler is not a LexicalHandler");
                }
                this.b = (LexicalHandler) obj;
                return;
            }
        }
        if (str.equals("http://www.ccil.org/~cowan/tagsoup/properties/scanner")) {
            if (!(obj instanceof g)) {
                throw new SAXNotSupportedException("Your scanner is not a Scanner");
            }
            this.g = (g) obj;
        } else if (str.equals("http://www.ccil.org/~cowan/tagsoup/properties/schema")) {
            if (!(obj instanceof d)) {
                throw new SAXNotSupportedException("Your schema is not a Schema");
            }
            this.f = (d) obj;
        } else {
            if (!str.equals("http://www.ccil.org/~cowan/tagsoup/properties/auto-detector")) {
                throw new SAXNotRecognizedException("Unknown property ".concat(str));
            }
            if (!(obj instanceof e)) {
                throw new SAXNotSupportedException("Your auto-detector is not an AutoDetector");
            }
            this.h = (e) obj;
        }
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void startCDATA() {
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void startDTD(String str, String str2, String str3) {
    }

    @Override // org.xml.sax.ext.LexicalHandler
    public final void startEntity(String str) {
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:117:0x02de  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x02e2  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x039d  */
    /* JADX WARN: Removed duplicated region for block: B:199:0x0429 A[PHI: r14 r17
  0x0429: PHI (r14v8 boolean) = (r14v13 boolean), (r14v14 boolean), (r14v15 boolean) binds: [B:215:0x044f, B:205:0x0435, B:198:0x0427] A[DONT_GENERATE, DONT_INLINE]
  0x0429: PHI (r17v4 boolean) = (r17v9 boolean), (r17v10 boolean), (r17v11 boolean) binds: [B:215:0x044f, B:205:0x0435, B:198:0x0427] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:243:0x04b9  */
    /* JADX WARN: Removed duplicated region for block: B:246:0x04c8  */
    /* JADX WARN: Type inference failed for: r1v65, types: [boolean] */
    @Override // org.xml.sax.XMLReader
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void parse(org.xml.sax.InputSource r22) throws org.xml.sax.SAXException, java.io.IOException {
        /*
            Method dump skipped, instructions count: 1802
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.ccil.cowan.tagsoup.f.parse(org.xml.sax.InputSource):void");
    }
}
