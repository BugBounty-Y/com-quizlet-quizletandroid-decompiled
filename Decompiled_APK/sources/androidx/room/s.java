package androidx.room;

import com.google.android.gms.internal.mlkit_vision_camera.U1;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes.dex */
public final class s implements kotlinx.serialization.modules.e {
    public final /* synthetic */ int a;
    public String b;
    public boolean c;

    @Override // kotlinx.serialization.modules.e
    public void c(kotlin.reflect.c kClass, com.sdk.growthbook.utils.a provider) {
        Intrinsics.checkNotNullParameter(kClass, "kClass");
        Intrinsics.checkNotNullParameter(provider, "provider");
    }

    @Override // kotlinx.serialization.modules.e
    public void d(kotlin.reflect.c baseClass, Function1 defaultSerializerProvider) {
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(defaultSerializerProvider, "defaultSerializerProvider");
    }

    @Override // kotlinx.serialization.modules.e
    public void e(kotlin.reflect.c baseClass, kotlin.reflect.c actualClass, KSerializer actualSerializer) {
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(actualClass, "actualClass");
        Intrinsics.checkNotNullParameter(actualSerializer, "actualSerializer");
        SerialDescriptor descriptor = actualSerializer.getDescriptor();
        U1 u1E = descriptor.e();
        if ((u1E instanceof kotlinx.serialization.descriptors.d) || Intrinsics.b(u1E, kotlinx.serialization.descriptors.h.b)) {
            throw new IllegalArgumentException("Serializer for " + ((C4950i) actualClass).f() + " can't be registered as a subclass for polymorphic serialization because its kind " + u1E + " is not concrete. To work with multiple hierarchies, register it as a base class.");
        }
        boolean z = this.c;
        if (z && (Intrinsics.b(u1E, kotlinx.serialization.descriptors.j.c) || Intrinsics.b(u1E, kotlinx.serialization.descriptors.j.d) || (u1E instanceof kotlinx.serialization.descriptors.f) || (u1E instanceof kotlinx.serialization.descriptors.i))) {
            throw new IllegalArgumentException("Serializer for " + ((C4950i) actualClass).f() + " of kind " + u1E + " cannot be serialized polymorphically with class discriminator.");
        }
        if (z) {
            int iF = descriptor.f();
            for (int i = 0; i < iF; i++) {
                String strG = descriptor.g(i);
                if (Intrinsics.b(strG, this.b)) {
                    throw new IllegalArgumentException("Polymorphic serializer for " + actualClass + " has property '" + strG + "' that conflicts with JSON class discriminator. You can either change class discriminator in JsonConfiguration, rename property with @SerialName annotation or fall back to array polymorphism");
                }
            }
        }
    }

    @Override // kotlinx.serialization.modules.e
    public void f(kotlin.reflect.c baseClass, Function1 defaultDeserializerProvider) {
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(defaultDeserializerProvider, "defaultDeserializerProvider");
    }

    public String toString() {
        switch (this.a) {
            case 1:
                String str = this.c ? "Applink" : "Unclassified";
                String str2 = this.b;
                if (str2 == null) {
                    return str;
                }
                return str + '(' + str2 + ')';
            case 4:
                StringBuilder sb = new StringBuilder("OTGlobalUIProperty{shouldShowlinkUnderline=");
                sb.append(this.c);
                sb.append(", linkColor='");
                return android.support.v4.media.session.a.t(sb, this.b, "'}");
            default:
                return super.toString();
        }
    }

    public /* synthetic */ s(String str, int i, boolean z) {
        this.a = i;
        this.b = str;
        this.c = z;
    }

    public s(kotlinx.serialization.json.i configuration) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        this.b = configuration.g;
        this.c = configuration.j != kotlinx.serialization.json.a.a;
    }

    public s(boolean z, String str) {
        this.a = 0;
        this.c = z;
        this.b = str;
    }
}
