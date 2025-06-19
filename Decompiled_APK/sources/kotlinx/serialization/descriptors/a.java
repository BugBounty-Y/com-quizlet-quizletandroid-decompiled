package kotlinx.serialization.descriptors;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public List b;
    public final ArrayList c;
    public final HashSet d;
    public final ArrayList e;
    public final ArrayList f;
    public final ArrayList g;

    public a(String serialName) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        this.a = serialName;
        this.b = K.a;
        this.c = new ArrayList();
        this.d = new HashSet();
        this.e = new ArrayList();
        this.f = new ArrayList();
        this.g = new ArrayList();
    }

    public static void a(a aVar, String elementName, SerialDescriptor descriptor) {
        K annotations = K.a;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(elementName, "elementName");
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        Intrinsics.checkNotNullParameter(annotations, "annotations");
        if (!aVar.d.add(elementName)) {
            StringBuilder sbY = android.support.v4.media.session.a.y("Element with name '", elementName, "' is already registered in ");
            sbY.append(aVar.a);
            throw new IllegalArgumentException(sbY.toString().toString());
        }
        aVar.c.add(elementName);
        aVar.e.add(descriptor);
        aVar.f.add(annotations);
        aVar.g.add(false);
    }
}
