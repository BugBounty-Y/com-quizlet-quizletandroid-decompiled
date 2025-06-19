package androidx.navigation.serialization;

import androidx.camera.camera2.internal.p0;
import androidx.navigation.AbstractC1285g;
import androidx.navigation.S;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import java.util.LinkedHashMap;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes.dex */
public final class h extends W1 {
    public final KSerializer a;
    public final LinkedHashMap b;
    public final p0 c;
    public final LinkedHashMap d;
    public int e;

    public h(KSerializer serializer, LinkedHashMap typeMap) {
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(typeMap, "typeMap");
        this.a = serializer;
        this.b = typeMap;
        this.c = kotlinx.serialization.modules.f.a;
        this.d = new LinkedHashMap();
        this.e = -1;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1
    public final void L(SerialDescriptor descriptor, int i) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        this.e = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1
    public final void M(Object value) {
        Intrinsics.checkNotNullParameter(value, "value");
        O(value);
    }

    public final void O(Object obj) {
        String strG = this.a.getDescriptor().g(this.e);
        S s = (S) this.b.get(strG);
        if (s == null) {
            throw new IllegalStateException(android.support.v4.media.session.a.B("Cannot find NavType for argument ", strG, ". Please provide NavType through typeMap.").toString());
        }
        this.d.put(strG, s instanceof AbstractC1285g ? ((AbstractC1285g) s).i(obj) : A.b(s.f(obj)));
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final p0 a() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final void d() {
        O(null);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.W1, kotlinx.serialization.encoding.Encoder
    public final Encoder x(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        if (d.e(descriptor)) {
            this.e = 0;
        }
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this;
    }

    @Override // kotlinx.serialization.encoding.Encoder
    public final void y(KSerializer serializer, Object obj) {
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        O(obj);
    }
}
