package com.google.android.gms.internal.mlkit_vision_camera;

import android.database.Cursor;
import androidx.compose.material3.W4;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;

/* loaded from: classes2.dex */
public abstract class V1 implements Decoder, kotlinx.serialization.encoding.a {
    public static final void E(int i, int i2, androidx.compose.ui.graphics.painter.b actionIcon, String actionContentDescription, androidx.compose.ui.n nVar, boolean z, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i3) {
        C0814p c0814p;
        boolean z2;
        androidx.compose.ui.n nVar2;
        int i4 = 1;
        int i5 = 16;
        Intrinsics.checkNotNullParameter(actionIcon, "actionIcon");
        Intrinsics.checkNotNullParameter(actionContentDescription, "actionContentDescription");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(155827171);
        if (((i3 | (c0814p2.d(i) ? 4 : 2) | (c0814p2.d(i2) ? 32 : 16) | (c0814p2.h(actionIcon) ? 256 : 128) | (c0814p2.f(actionContentDescription) ? 2048 : 1024) | 221184 | (c0814p2.h(function0) ? 1048576 : 524288) | (c0814p2.h(function02) ? 8388608 : 4194304)) & 4793491) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            z2 = z;
            c0814p = c0814p2;
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            float f = W4.a;
            androidx.compose.material3.D.a(androidx.compose.runtime.internal.e.e(-645650616, new com.quizlet.features.flashcards.views.b(i, i2, i4), c0814p2), nVar3, androidx.compose.runtime.internal.e.e(1681511754, new com.quizlet.explanations.questiondetail.ui.composables.m(i5, function0), c0814p2), androidx.compose.runtime.internal.e.e(-1998651405, new com.quizlet.assembly.compose.input.h(10, actionIcon, actionContentDescription, function02, false), c0814p2), DefinitionKt.NO_Float_VALUE, null, W4.c(((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, 0L, 0L, c0814p2, 30), c0814p2, 3510, 176);
            c0814p = c0814p2;
            z2 = true;
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.modals.h(i, i2, actionIcon, actionContentDescription, nVar2, z2, function0, function02, i3);
        }
    }

    public static final int G(Cursor c, String name) {
        Intrinsics.checkNotNullParameter(c, "c");
        Intrinsics.checkNotNullParameter(name, "name");
        int columnIndex = c.getColumnIndex(name);
        if (columnIndex >= 0) {
            return columnIndex;
        }
        int columnIndex2 = c.getColumnIndex("`" + name + '`');
        if (columnIndex2 >= 0) {
            return columnIndex2;
        }
        return -1;
    }

    public static final int H(Cursor c, String name) {
        String strH;
        Intrinsics.checkNotNullParameter(c, "c");
        Intrinsics.checkNotNullParameter(name, "name");
        int iG = G(c, name);
        if (iG >= 0) {
            return iG;
        }
        try {
            String[] columnNames = c.getColumnNames();
            Intrinsics.checkNotNullExpressionValue(columnNames, "c.columnNames");
            strH = C4933y.H(columnNames, null, null, 63);
        } catch (Exception unused) {
            strH = DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.m("column '", name, "' does not exist. Available columns: ", strH));
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public byte A() {
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.Byte");
        return ((Byte) objF).byteValue();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public short B() {
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.Short");
        return ((Short) objF).shortValue();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public float C() {
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.Float");
        return ((Float) objF).floatValue();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public double D() {
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.Double");
        return ((Double) objF).doubleValue();
    }

    public Object F() {
        throw new SerializationException(kotlin.jvm.internal.K.a(getClass()) + " can't retrieve untyped values");
    }

    @Override // kotlinx.serialization.encoding.a
    public void b(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public kotlinx.serialization.encoding.a c(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this;
    }

    @Override // kotlinx.serialization.encoding.a
    public short d(kotlinx.serialization.internal.f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return B();
    }

    @Override // kotlinx.serialization.encoding.a
    public float e(kotlinx.serialization.internal.f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return C();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public boolean f() {
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.Boolean");
        return ((Boolean) objF).booleanValue();
    }

    @Override // kotlinx.serialization.encoding.a
    public char g(kotlinx.serialization.internal.f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return h();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public char h() {
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.Char");
        return ((Character) objF).charValue();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public int i(SerialDescriptor enumDescriptor) {
        Intrinsics.checkNotNullParameter(enumDescriptor, "enumDescriptor");
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.Int");
        return ((Integer) objF).intValue();
    }

    @Override // kotlinx.serialization.encoding.a
    public long j(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return p();
    }

    @Override // kotlinx.serialization.encoding.a
    public byte k(kotlinx.serialization.internal.f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return A();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public int m() {
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.Int");
        return ((Integer) objF).intValue();
    }

    @Override // kotlinx.serialization.encoding.a
    public int n(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return m();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public String o() {
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.String");
        return (String) objF;
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public long p() {
        Object objF = F();
        Intrinsics.e(objF, "null cannot be cast to non-null type kotlin.Long");
        return ((Long) objF).longValue();
    }

    @Override // kotlinx.serialization.encoding.a
    public boolean q(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return f();
    }

    @Override // kotlinx.serialization.encoding.a
    public String r(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return o();
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public boolean s() {
        return true;
    }

    @Override // kotlinx.serialization.encoding.a
    public Object v(SerialDescriptor descriptor, int i, KSerializer deserializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        if (!deserializer.getDescriptor().c() && !s()) {
            return null;
        }
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        return u(deserializer);
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public Decoder w(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this;
    }

    @Override // kotlinx.serialization.encoding.a
    public Decoder x(kotlinx.serialization.internal.f0 descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return w(descriptor.i(i));
    }

    @Override // kotlinx.serialization.encoding.a
    public double y(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return D();
    }

    @Override // kotlinx.serialization.encoding.a
    public Object z(SerialDescriptor descriptor, int i, KSerializer deserializer, Object obj) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        return u(deserializer);
    }
}
