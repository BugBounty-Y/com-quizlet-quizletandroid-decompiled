package io.ktor.http;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3135e7;
import com.google.android.gms.internal.mlkit_vision_barcode.s7;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.collections.C;
import kotlin.collections.J;
import kotlin.collections.K;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* loaded from: classes3.dex */
public final class w {
    public static final A k;
    public String a;
    public boolean b;
    public int c;
    public y d;
    public String e;
    public String f;
    public String g;
    public List h;
    public u i;
    public com.quizlet.login.common.interactors.d j;

    static {
        Intrinsics.checkNotNullParameter(new j(), "<this>");
        Intrinsics.checkNotNullParameter("http://localhost", "urlString");
        Intrinsics.checkNotNullParameter("http://localhost", "urlString");
        k = x.b(new w(), "http://localhost").b();
    }

    public w() {
        K pathSegments = K.a;
        s.b.getClass();
        f parameters = f.c;
        Intrinsics.checkNotNullParameter("", "host");
        Intrinsics.checkNotNullParameter(pathSegments, "pathSegments");
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        Intrinsics.checkNotNullParameter("", "fragment");
        this.a = "";
        this.b = false;
        this.c = 0;
        this.d = null;
        this.e = null;
        this.f = null;
        Set set = AbstractC4879a.a;
        Charset charset = Charsets.UTF_8;
        Intrinsics.checkNotNullParameter("", "<this>");
        Intrinsics.checkNotNullParameter(charset, "charset");
        StringBuilder sb = new StringBuilder();
        CharsetEncoder charsetEncoderNewEncoder = charset.newEncoder();
        Intrinsics.checkNotNullExpressionValue(charsetEncoderNewEncoder, "newEncoder(...)");
        int length = "".length();
        Intrinsics.checkNotNullParameter(charsetEncoderNewEncoder, "<this>");
        Intrinsics.checkNotNullParameter("", "input");
        kotlinx.io.a dst = new kotlinx.io.a();
        Intrinsics.checkNotNullParameter(charsetEncoderNewEncoder, "<this>");
        Intrinsics.checkNotNullParameter(dst, "destination");
        Intrinsics.checkNotNullParameter("", "input");
        if (length > 0) {
            int i = 0;
            do {
                Intrinsics.checkNotNullParameter(charsetEncoderNewEncoder, "<this>");
                Intrinsics.checkNotNullParameter("", "input");
                Intrinsics.checkNotNullParameter(dst, "dst");
                byte[] bArrC = s7.c(charsetEncoderNewEncoder, "", i, length);
                dst.j(bArrC.length, bArrC);
                int length2 = bArrC.length;
                if (length2 < 0) {
                    throw new IllegalStateException("Check failed.");
                }
                i += length2;
            } while (i < length);
        }
        AbstractC4879a.f(dst, new com.quizlet.ui.compose.modifiers.b(sb, 9));
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        this.g = string;
        ArrayList arrayList = new ArrayList(C.q(pathSegments, 10));
        J.a.getClass();
        this.h = arrayList;
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        u uVar = new u(13);
        for (String name : M.a) {
            parameters.getClass();
            Intrinsics.checkNotNullParameter(name, "name");
            K k2 = K.a;
            String strE = AbstractC4879a.e(name, false);
            ArrayList arrayList2 = new ArrayList(C.q(k2, 10));
            J.a.getClass();
            uVar.e(strE, arrayList2);
        }
        this.i = uVar;
        this.j = new com.quizlet.login.common.interactors.d(uVar);
    }

    public final void a() {
        if (this.a.length() <= 0 && !Intrinsics.b(c().a, "file")) {
            A a = k;
            this.a = a.a;
            if (this.d == null) {
                this.d = a.f;
            }
            if (this.c == 0) {
                e(a.b);
            }
        }
    }

    public final A b() {
        a();
        y yVar = this.d;
        String str = this.a;
        int i = this.c;
        List list = this.h;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(AbstractC4879a.c((String) it2.next()));
        }
        s sVarB = AbstractC3135e7.b((u) this.j.b);
        String strD = AbstractC4879a.d(0, 0, this.g, 15);
        String str2 = this.e;
        String strC = str2 != null ? AbstractC4879a.c(str2) : null;
        String str3 = this.f;
        String strC2 = str3 != null ? AbstractC4879a.c(str3) : null;
        a();
        StringBuilder sb = new StringBuilder(256);
        AbstractC3108b7.b(this, sb);
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return new A(yVar, str, i, arrayList, sVarB, strD, strC, strC2, string);
    }

    public final y c() {
        y yVar = this.d;
        if (yVar != null) {
            return yVar;
        }
        y yVar2 = y.c;
        return y.c;
    }

    public final void d(String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.a = str;
    }

    public final void e(int i) {
        if (i < 0 || i >= 65536) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Port must be between 0 and 65535, or 0 if not set. Provided: ").toString());
        }
        this.c = i;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder(256);
        AbstractC3108b7.b(this, sb);
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}
