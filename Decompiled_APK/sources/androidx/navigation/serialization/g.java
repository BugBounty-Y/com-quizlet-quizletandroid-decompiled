package androidx.navigation.serialization;

import android.os.Bundle;
import androidx.camera.camera2.internal.p0;
import androidx.navigation.S;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.V1;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;

/* loaded from: classes.dex */
public final class g extends V1 {
    public final com.quizlet.data.repository.activitycenter.b a;
    public int b;
    public String c;
    public final p0 d;

    public g(Bundle bundle, LinkedHashMap typeMap) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(typeMap, "typeMap");
        this.b = -1;
        this.c = "";
        this.d = kotlinx.serialization.modules.f.a;
        this.a = new com.quizlet.data.repository.activitycenter.b(bundle, typeMap);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1
    public final Object F() {
        return I();
    }

    public final Object I() {
        String key = this.c;
        com.quizlet.data.repository.activitycenter.b bVar = this.a;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        S s = (S) ((LinkedHashMap) bVar.c).get(key);
        Object objA = s != null ? s.a((Bundle) bVar.b, key) : null;
        if (objA != null) {
            return objA;
        }
        throw new IllegalStateException(("Unexpected null value for non-nullable argument " + this.c).toString());
    }

    @Override // kotlinx.serialization.encoding.Decoder, kotlinx.serialization.encoding.a
    public final p0 a() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final boolean s() {
        String key = this.c;
        com.quizlet.data.repository.activitycenter.b bVar = this.a;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        S s = (S) ((LinkedHashMap) bVar.c).get(key);
        return (s != null ? s.a((Bundle) bVar.b, key) : null) != null;
    }

    @Override // kotlinx.serialization.encoding.a
    public final int t(SerialDescriptor descriptor) {
        String key;
        Bundle source;
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        int i = this.b;
        do {
            i++;
            if (i >= descriptor.f()) {
                return -1;
            }
            key = descriptor.g(i);
            com.quizlet.data.repository.activitycenter.b bVar = this.a;
            bVar.getClass();
            Intrinsics.checkNotNullParameter(key, "key");
            source = (Bundle) bVar.b;
            Intrinsics.checkNotNullParameter(source, "source");
        } while (!AbstractC3335e2.a(source, key));
        this.b = i;
        this.c = key;
        return i;
    }

    @Override // kotlinx.serialization.encoding.Decoder
    public final Object u(KSerializer deserializer) {
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        return I();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.V1, kotlinx.serialization.encoding.Decoder
    public final Decoder w(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        if (d.e(descriptor)) {
            this.c = descriptor.g(0);
            this.b = 0;
        }
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        return this;
    }
}
