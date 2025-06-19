package kotlinx.serialization.json.internal;

import androidx.camera.camera2.internal.p0;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import kotlin.A;
import kotlin.C;
import kotlin.D;
import kotlin.G;
import kotlin.H;
import kotlin.jvm.internal.Intrinsics;
import kotlin.z;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public final class b extends W1 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ n b;
    public final /* synthetic */ String c;
    public final Object d;

    public b(n nVar, String str) {
        this.b = nVar;
        this.c = str;
        this.d = nVar.b.b;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public void B(long j) {
        switch (this.a) {
            case 1:
                C c = D.b;
                O(Long.toUnsignedString(j));
                break;
            default:
                super.B(j);
                break;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public void E(String value) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(value, "value");
                this.b.M(this.c, new kotlinx.serialization.json.r(value, false, (SerialDescriptor) this.d));
                break;
            default:
                super.E(value);
                break;
        }
    }

    public void O(String s) {
        Intrinsics.checkNotNullParameter(s, "s");
        this.b.M(this.c, new kotlinx.serialization.json.r(s, false, null));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final p0 a() {
        switch (this.a) {
            case 0:
                return this.b.b.b;
            default:
                return (p0) this.d;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public void f(short s) {
        switch (this.a) {
            case 1:
                G g = H.b;
                O(String.valueOf(s & 65535));
                break;
            default:
                super.f(s);
                break;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public void j(byte b) {
        switch (this.a) {
            case 1:
                kotlin.w wVar = kotlin.x.b;
                O(String.valueOf(b & 255));
                break;
            default:
                super.j(b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public void w(int i) {
        switch (this.a) {
            case 1:
                z zVar = A.b;
                O(Integer.toUnsignedString(i));
                break;
            default:
                super.w(i);
                break;
        }
    }

    public b(n nVar, String str, SerialDescriptor serialDescriptor) {
        this.b = nVar;
        this.c = str;
        this.d = serialDescriptor;
    }
}
