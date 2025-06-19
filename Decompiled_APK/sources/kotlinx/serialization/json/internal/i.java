package kotlinx.serialization.json.internal;

import androidx.camera.camera2.internal.p0;
import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_camera.V1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.J;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public final class i extends V1 {
    public final androidx.camera.camera2.internal.concurrent.a a;
    public final p0 b;

    public i(androidx.camera.camera2.internal.concurrent.a lexer, kotlinx.serialization.json.c json) {
        Intrinsics.checkNotNullParameter(lexer, "lexer");
        Intrinsics.checkNotNullParameter(json, "json");
        this.a = lexer;
        this.b = json.b;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final byte A() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.a;
        String strM = aVar.m();
        try {
            return J.d(strM);
        } catch (IllegalArgumentException unused) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, B.h("Failed to parse type 'UByte' for input '", strM, '\''), 0, null, 6);
            throw null;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final short B() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.a;
        String strM = aVar.m();
        try {
            return J.i(strM);
        } catch (IllegalArgumentException unused) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, B.h("Failed to parse type 'UShort' for input '", strM, '\''), 0, null, 6);
            throw null;
        }
    }

    @Override // kotlinx.serialization.encoding.Decoder, kotlinx.serialization.encoding.a
    public final p0 a() {
        return this.b;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final int m() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.a;
        String strM = aVar.m();
        try {
            return J.e(strM);
        } catch (IllegalArgumentException unused) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, B.h("Failed to parse type 'UInt' for input '", strM, '\''), 0, null, 6);
            throw null;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final long p() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.a;
        String strM = aVar.m();
        try {
            return J.g(strM);
        } catch (IllegalArgumentException unused) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, B.h("Failed to parse type 'ULong' for input '", strM, '\''), 0, null, 6);
            throw null;
        }
    }

    @Override // kotlinx.serialization.encoding.a
    public final int t(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        throw new IllegalStateException("unsupported");
    }
}
