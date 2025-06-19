package com.quizlet.remote.util;

import androidx.compose.ui.node.B;
import com.squareup.moshi.H;
import com.squareup.moshi.JsonDataException;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.r;
import com.squareup.moshi.s;
import com.squareup.moshi.w;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import okio.AbstractC5085b;
import okio.InterfaceC5093j;
import okio.z;

/* loaded from: classes3.dex */
public final class c extends l {
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i) {
        this.a = i;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IOException {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(reader, "reader");
                InterfaceC5093j interfaceC5093jD = reader.D();
                try {
                    String strU = interfaceC5093jD.U();
                    interfaceC5093jD.close();
                    return strU;
                } finally {
                }
            case 1:
                return reader.P();
            case 2:
                return Boolean.valueOf(reader.p());
            case 3:
                return Byte.valueOf((byte) H.g(reader, "a byte", -128, 255));
            case 4:
                String strP = reader.P();
                if (strP.length() <= 1) {
                    return Character.valueOf(strP.charAt(0));
                }
                throw new JsonDataException(android.support.v4.media.session.a.m("Expected a char but was ", B.h("\"", strP, '\"'), " at path ", reader.j()));
            case 5:
                return Double.valueOf(reader.q());
            case 6:
                float fQ = (float) reader.q();
                if (reader.e || !Float.isInfinite(fQ)) {
                    return Float.valueOf(fQ);
                }
                throw new JsonDataException("JSON forbids NaN and infinities: " + fQ + " at path " + reader.j());
            case 7:
                return Integer.valueOf(reader.r());
            case 8:
                return Long.valueOf(reader.y());
            default:
                return Short.valueOf((short) H.g(reader, "a short", -32768, 32767));
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        switch (this.a) {
            case 0:
                String str = (String) obj;
                Intrinsics.checkNotNullParameter(writer, "writer");
                s sVar = (s) writer;
                if (sVar.f) {
                    throw new IllegalStateException("BufferedSink cannot be used as a map key in JSON at path " + sVar.i());
                }
                sVar.c0();
                sVar.P();
                int[] iArr = sVar.b;
                int i = sVar.a;
                sVar.a = i + 1;
                iArr[i] = 9;
                z zVarB = AbstractC5085b.b(new r(sVar));
                try {
                    if (str == null) {
                        throw new IllegalStateException("Required value was null.");
                    }
                    zVarB.H(str);
                    zVarB.close();
                    return;
                } finally {
                }
            case 1:
                writer.C((String) obj);
                return;
            case 2:
                writer.D(((Boolean) obj).booleanValue());
                return;
            case 3:
                writer.y(((Byte) obj).intValue() & 255);
                return;
            case 4:
                writer.C(((Character) obj).toString());
                return;
            case 5:
                writer.r(((Double) obj).doubleValue());
                return;
            case 6:
                Float f = (Float) obj;
                f.getClass();
                writer.B(f);
                return;
            case 7:
                writer.y(((Integer) obj).intValue());
                return;
            case 8:
                writer.y(((Long) obj).longValue());
                return;
            default:
                writer.y(((Short) obj).intValue());
                return;
        }
    }

    public String toString() {
        switch (this.a) {
            case 1:
                return "JsonAdapter(String)";
            case 2:
                return "JsonAdapter(Boolean)";
            case 3:
                return "JsonAdapter(Byte)";
            case 4:
                return "JsonAdapter(Character)";
            case 5:
                return "JsonAdapter(Double)";
            case 6:
                return "JsonAdapter(Float)";
            case 7:
                return "JsonAdapter(Integer)";
            case 8:
                return "JsonAdapter(Long)";
            case 9:
                return "JsonAdapter(Short)";
            default:
                return super.toString();
        }
    }
}
