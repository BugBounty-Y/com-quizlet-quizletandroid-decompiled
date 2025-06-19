package kotlinx.serialization.json;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.N;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.E;
import kotlinx.serialization.internal.q0;

/* loaded from: classes3.dex */
public final class w implements SerialDescriptor {
    public static final w b = new w();
    public static final String c = "kotlinx.serialization.json.JsonObject";
    public final /* synthetic */ E a;

    public w() {
        R1.g(N.a);
        q0 q0Var = q0.a;
        this.a = R1.b(m.a).d;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final String a() {
        return c;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean c() {
        this.a.getClass();
        return false;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final int d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return this.a.d(name);
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final U1 e() {
        this.a.getClass();
        return kotlinx.serialization.descriptors.j.d;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final int f() {
        this.a.getClass();
        return 2;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final String g(int i) {
        this.a.getClass();
        return String.valueOf(i);
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final List getAnnotations() {
        this.a.getClass();
        return K.a;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final List h(int i) {
        return this.a.h(i);
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final SerialDescriptor i(int i) {
        return this.a.i(i);
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean isInline() {
        this.a.getClass();
        return false;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean j(int i) {
        this.a.j(i);
        return false;
    }
}
