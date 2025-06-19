package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.b7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3108b7 {
    public static final void a(com.quizlet.assembly.compose.modals.x modalState, String title, String description, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1255716240);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p.f(modalState) : c0814p.h(modalState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(title) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.f(description) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.google.android.gms.internal.mlkit_vision_document_scanner.U5.b(modalState, nVar3, false, null, null, null, androidx.compose.runtime.internal.e.e(1678032693, new com.quizlet.assembly.compose.input.l(2, title, description), c0814p), c0814p, (i3 & 14) | 1572872 | ((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND), 60);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) modalState, (Object) title, (Object) description, (Object) nVar2, i, 16);
        }
    }

    public static final void b(io.ktor.http.w wVar, StringBuilder sb) {
        List listB;
        sb.append(wVar.c().a);
        String str = wVar.c().a;
        int iHashCode = str.hashCode();
        if (iHashCode != -1081572750) {
            if (iHashCode != 3143036) {
                if (iHashCode == 92611469 && str.equals("about")) {
                    CharSequence charSequence = wVar.a;
                    sb.append(":");
                    sb.append(charSequence);
                    return;
                }
            } else if (str.equals("file")) {
                CharSequence charSequence2 = wVar.a;
                String strH = h(wVar);
                sb.append("://");
                sb.append(charSequence2);
                if (!StringsKt.X(strH, '/')) {
                    sb.append('/');
                }
                sb.append((CharSequence) strH);
                return;
            }
        } else if (str.equals("mailto")) {
            Intrinsics.checkNotNullParameter(wVar, "<this>");
            StringBuilder sb2 = new StringBuilder();
            String str2 = wVar.e;
            String str3 = wVar.f;
            Intrinsics.checkNotNullParameter(sb2, "<this>");
            if (str2 != null) {
                sb2.append(str2);
                if (str3 != null) {
                    sb2.append(':');
                    sb2.append(str3);
                }
                sb2.append("@");
            }
            CharSequence string = sb2.toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            CharSequence charSequence3 = wVar.a;
            sb.append(":");
            sb.append(string);
            sb.append(charSequence3);
            return;
        }
        sb.append("://");
        sb.append(g(wVar));
        String encodedPath = h(wVar);
        io.ktor.http.u encodedQueryParameters = wVar.i;
        boolean z = wVar.b;
        Intrinsics.checkNotNullParameter(sb, "<this>");
        Intrinsics.checkNotNullParameter(encodedPath, "encodedPath");
        Intrinsics.checkNotNullParameter(encodedQueryParameters, "encodedQueryParameters");
        if (!StringsKt.O(encodedPath) && !kotlin.text.D.r(encodedPath, "/", false)) {
            sb.append('/');
        }
        sb.append((CharSequence) encodedPath);
        if (!((Map) encodedQueryParameters.b).isEmpty() || z) {
            sb.append("?");
        }
        Set<Map.Entry> setA = encodedQueryParameters.a();
        ArrayList arrayList = new ArrayList();
        for (Map.Entry entry : setA) {
            String str4 = (String) entry.getKey();
            List list = (List) entry.getValue();
            if (list.isEmpty()) {
                listB = kotlin.collections.A.b(new Pair(str4, null));
            } else {
                ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList2.add(new Pair(str4, (String) it2.next()));
                }
                listB = arrayList2;
            }
            kotlin.collections.G.u(arrayList, listB);
        }
        CollectionsKt.R(arrayList, sb, "&", new com.sdk.growthbook.utils.a(15), 60);
        if (wVar.g.length() > 0) {
            sb.append('#');
            sb.append(wVar.g);
        }
    }

    public static void c(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception unused) {
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static long[] d(Serializable serializable) {
        if (!(serializable instanceof int[])) {
            if (serializable instanceof long[]) {
                return (long[]) serializable;
            }
            return null;
        }
        int[] iArr = (int[]) serializable;
        long[] jArr = new long[iArr.length];
        for (int i = 0; i < iArr.length; i++) {
            jArr[i] = iArr[i];
        }
        return jArr;
    }

    public static void e(androidx.exifinterface.media.b bVar, androidx.exifinterface.media.c cVar, int i) {
        byte[] bArr = new byte[8192];
        while (i > 0) {
            int iMin = Math.min(i, 8192);
            int i2 = bVar.read(bArr, 0, iMin);
            if (i2 != iMin) {
                throw new IOException("Failed to copy the given amount of bytes from the inputstream to the output stream.");
            }
            i -= i2;
            cVar.write(bArr, 0, i2);
        }
    }

    public static void f(InputStream inputStream, OutputStream outputStream) {
        byte[] bArr = new byte[8192];
        while (true) {
            int i = inputStream.read(bArr);
            if (i == -1) {
                return;
            } else {
                outputStream.write(bArr, 0, i);
            }
        }
    }

    public static final String g(io.ktor.http.w wVar) {
        Intrinsics.checkNotNullParameter(wVar, "<this>");
        StringBuilder sb = new StringBuilder();
        Intrinsics.checkNotNullParameter(wVar, "<this>");
        StringBuilder sb2 = new StringBuilder();
        String str = wVar.e;
        String str2 = wVar.f;
        Intrinsics.checkNotNullParameter(sb2, "<this>");
        if (str != null) {
            sb2.append(str);
            if (str2 != null) {
                sb2.append(':');
                sb2.append(str2);
            }
            sb2.append("@");
        }
        String string = sb2.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        sb.append(string);
        sb.append(wVar.a);
        int i = wVar.c;
        if (i != 0 && i != wVar.c().b) {
            sb.append(":");
            sb.append(String.valueOf(wVar.c));
        }
        String string2 = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
        return string2;
    }

    public static final String h(io.ktor.http.w wVar) {
        Intrinsics.checkNotNullParameter(wVar, "<this>");
        List list = wVar.h;
        return list.isEmpty() ? "" : list.size() == 1 ? ((CharSequence) CollectionsKt.L(list)).length() == 0 ? "/" : (String) CollectionsKt.L(list) : CollectionsKt.S(list, "/", null, null, null, 62);
    }

    public static final void i(io.ktor.http.w wVar, String value) {
        Intrinsics.checkNotNullParameter(wVar, "<this>");
        Intrinsics.checkNotNullParameter(value, "value");
        List listY0 = StringsKt.O(value) ? kotlin.collections.K.a : value.equals("/") ? io.ktor.http.x.a : CollectionsKt.y0(StringsKt.V(value, new char[]{'/'}));
        wVar.getClass();
        Intrinsics.checkNotNullParameter(listY0, "<set-?>");
        wVar.h = listY0;
    }

    public static boolean j(byte[] bArr, byte[] bArr2) {
        if (bArr2 != null && bArr.length >= bArr2.length) {
            for (int i = 0; i < bArr2.length; i++) {
                if (bArr[i] == bArr2[i]) {
                }
            }
            return true;
        }
        return false;
    }
}
