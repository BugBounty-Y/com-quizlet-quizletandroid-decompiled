package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.work.AbstractC1438l;
import androidx.work.C1437k;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.Map;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import org.jsoup.parser.C5096b;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.s2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3390s2 {
    public static final void a(com.quizlet.features.practicetest.takingtest.data.G uiState, Function0 navigateUp, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        Intrinsics.checkNotNullParameter(navigateUp, "navigateUp");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-473028838);
        if (((i | (c0814p2.f(uiState) ? 4 : 2) | (c0814p2.h(navigateUp) ? 32 : 16) | 384) & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            qVar2 = qVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            c0814p = c0814p2;
            AbstractC0725t3.a(androidx.compose.ui.platform.N.G(nVar, "PracticeTestErrorScreen"), androidx.compose.runtime.internal.e.e(-1721255722, new com.quizlet.explanations.questiondetail.ui.composables.m(17, navigateUp), c0814p2), null, null, null, 0, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, null, androidx.compose.runtime.internal.e.e(-555896341, new com.quizlet.baseui.base.d(uiState, 7), c0814p2), c0814p, 805306416, 444);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 3, uiState, navigateUp, qVar2);
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.io.Serializable, java.lang.Double[]] */
    /* JADX WARN: Type inference failed for: r0v3, types: [java.io.Serializable, java.lang.Float[]] */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.io.Serializable, java.lang.Long[]] */
    /* JADX WARN: Type inference failed for: r0v5, types: [java.io.Serializable, java.lang.Integer[]] */
    /* JADX WARN: Type inference failed for: r0v6, types: [java.io.Serializable, java.lang.Byte[]] */
    /* JADX WARN: Type inference failed for: r0v7, types: [java.io.Serializable, java.lang.Boolean[]] */
    /* JADX WARN: Type inference failed for: r1v14, types: [java.io.Serializable, java.lang.String[]] */
    public static final Serializable b(DataInputStream dataInputStream, byte b) throws IOException {
        if (b == 0) {
            return null;
        }
        if (b == 1) {
            return Boolean.valueOf(dataInputStream.readBoolean());
        }
        if (b == 2) {
            return Byte.valueOf(dataInputStream.readByte());
        }
        if (b == 3) {
            return Integer.valueOf(dataInputStream.readInt());
        }
        if (b == 4) {
            return Long.valueOf(dataInputStream.readLong());
        }
        if (b == 5) {
            return Float.valueOf(dataInputStream.readFloat());
        }
        if (b == 6) {
            return Double.valueOf(dataInputStream.readDouble());
        }
        if (b == 7) {
            return dataInputStream.readUTF();
        }
        int i = 0;
        if (b == 8) {
            int i2 = dataInputStream.readInt();
            ?? r0 = new Boolean[i2];
            while (i < i2) {
                r0[i] = Boolean.valueOf(dataInputStream.readBoolean());
                i++;
            }
            return r0;
        }
        if (b == 9) {
            int i3 = dataInputStream.readInt();
            ?? r02 = new Byte[i3];
            while (i < i3) {
                r02[i] = Byte.valueOf(dataInputStream.readByte());
                i++;
            }
            return r02;
        }
        if (b == 10) {
            int i4 = dataInputStream.readInt();
            ?? r03 = new Integer[i4];
            while (i < i4) {
                r03[i] = Integer.valueOf(dataInputStream.readInt());
                i++;
            }
            return r03;
        }
        if (b == 11) {
            int i5 = dataInputStream.readInt();
            ?? r04 = new Long[i5];
            while (i < i5) {
                r04[i] = Long.valueOf(dataInputStream.readLong());
                i++;
            }
            return r04;
        }
        if (b == 12) {
            int i6 = dataInputStream.readInt();
            ?? r05 = new Float[i6];
            while (i < i6) {
                r05[i] = Float.valueOf(dataInputStream.readFloat());
                i++;
            }
            return r05;
        }
        if (b == 13) {
            int i7 = dataInputStream.readInt();
            ?? r06 = new Double[i7];
            while (i < i7) {
                r06[i] = Double.valueOf(dataInputStream.readDouble());
                i++;
            }
            return r06;
        }
        if (b != 14) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(b, "Unsupported type "));
        }
        int i8 = dataInputStream.readInt();
        ?? r1 = new String[i8];
        while (i < i8) {
            String utf = dataInputStream.readUTF();
            if (Intrinsics.b(utf, "androidx.work.Data-95ed6082-b8e9-46e8-a73f-ff56f00f5d9d")) {
                utf = null;
            }
            r1[i] = utf;
            i++;
        }
        return r1;
    }

    public static com.quizlet.data.repository.course.membership.c c(org.jsoup.nodes.n nVar) {
        com.quizlet.data.repository.course.membership.c cVar;
        org.jsoup.nodes.g gVarV = nVar.v();
        return (gVarV == null || (cVar = gVarV.k) == null) ? new com.quizlet.data.repository.course.membership.c(new C5096b()) : cVar;
    }

    public static byte[] d(C1437k data) {
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
            try {
                dataOutputStream.writeShort(-21521);
                dataOutputStream.writeShort(1);
                dataOutputStream.writeInt(data.a.size());
                for (Map.Entry entry : data.a.entrySet()) {
                    e(dataOutputStream, (String) entry.getKey(), entry.getValue());
                }
                dataOutputStream.flush();
                if (dataOutputStream.size() > 10240) {
                    throw new IllegalStateException("Data cannot occupy more than 10240 bytes when serialized");
                }
                byte[] byteArray = byteArrayOutputStream.toByteArray();
                dataOutputStream.close();
                Intrinsics.checkNotNullExpressionValue(byteArray, "{\n                ByteAr…          }\n            }");
                return byteArray;
            } finally {
            }
        } catch (IOException e) {
            androidx.work.z.c().b(AbstractC1438l.a, "Error in Data#toByteArray: ", e);
            return new byte[0];
        }
    }

    public static final void e(DataOutputStream dataOutputStream, String str, Object obj) throws IOException {
        int i;
        if (obj == null) {
            dataOutputStream.writeByte(0);
        } else if (obj instanceof Boolean) {
            dataOutputStream.writeByte(1);
            dataOutputStream.writeBoolean(((Boolean) obj).booleanValue());
        } else if (obj instanceof Byte) {
            dataOutputStream.writeByte(2);
            dataOutputStream.writeByte(((Number) obj).byteValue());
        } else if (obj instanceof Integer) {
            dataOutputStream.writeByte(3);
            dataOutputStream.writeInt(((Number) obj).intValue());
        } else if (obj instanceof Long) {
            dataOutputStream.writeByte(4);
            dataOutputStream.writeLong(((Number) obj).longValue());
        } else if (obj instanceof Float) {
            dataOutputStream.writeByte(5);
            dataOutputStream.writeFloat(((Number) obj).floatValue());
        } else if (obj instanceof Double) {
            dataOutputStream.writeByte(6);
            dataOutputStream.writeDouble(((Number) obj).doubleValue());
        } else if (obj instanceof String) {
            dataOutputStream.writeByte(7);
            dataOutputStream.writeUTF((String) obj);
        } else {
            if (!(obj instanceof Object[])) {
                throw new IllegalArgumentException("Unsupported value type " + kotlin.jvm.internal.K.a(obj.getClass()).f());
            }
            Object[] objArr = (Object[]) obj;
            C4950i c4950iA = kotlin.jvm.internal.K.a(objArr.getClass());
            if (c4950iA.equals(kotlin.jvm.internal.K.a(Boolean[].class))) {
                i = 8;
            } else if (c4950iA.equals(kotlin.jvm.internal.K.a(Byte[].class))) {
                i = 9;
            } else if (c4950iA.equals(kotlin.jvm.internal.K.a(Integer[].class))) {
                i = 10;
            } else if (c4950iA.equals(kotlin.jvm.internal.K.a(Long[].class))) {
                i = 11;
            } else if (c4950iA.equals(kotlin.jvm.internal.K.a(Float[].class))) {
                i = 12;
            } else if (c4950iA.equals(kotlin.jvm.internal.K.a(Double[].class))) {
                i = 13;
            } else {
                if (!c4950iA.equals(kotlin.jvm.internal.K.a(String[].class))) {
                    throw new IllegalArgumentException("Unsupported value type " + kotlin.jvm.internal.K.a(objArr.getClass()).e());
                }
                i = 14;
            }
            dataOutputStream.writeByte(i);
            dataOutputStream.writeInt(objArr.length);
            for (Object obj2 : objArr) {
                if (i == 8) {
                    Boolean bool = obj2 instanceof Boolean ? (Boolean) obj2 : null;
                    dataOutputStream.writeBoolean(bool != null ? bool.booleanValue() : false);
                } else if (i == 9) {
                    Byte b = obj2 instanceof Byte ? (Byte) obj2 : null;
                    dataOutputStream.writeByte(b != null ? b.byteValue() : (byte) 0);
                } else if (i == 10) {
                    Integer num = obj2 instanceof Integer ? (Integer) obj2 : null;
                    dataOutputStream.writeInt(num != null ? num.intValue() : 0);
                } else if (i == 11) {
                    Long l = obj2 instanceof Long ? (Long) obj2 : null;
                    dataOutputStream.writeLong(l != null ? l.longValue() : 0L);
                } else if (i == 12) {
                    Float f = obj2 instanceof Float ? (Float) obj2 : null;
                    dataOutputStream.writeFloat(f != null ? f.floatValue() : DefinitionKt.NO_Float_VALUE);
                } else if (i == 13) {
                    Double d = obj2 instanceof Double ? (Double) obj2 : null;
                    dataOutputStream.writeDouble(d != null ? d.doubleValue() : 0.0d);
                } else if (i == 14) {
                    String str2 = obj2 instanceof String ? (String) obj2 : null;
                    if (str2 == null) {
                        str2 = "androidx.work.Data-95ed6082-b8e9-46e8-a73f-ff56f00f5d9d";
                    }
                    dataOutputStream.writeUTF(str2);
                }
            }
        }
        dataOutputStream.writeUTF(str);
    }
}
