package kotlin.jvm.internal;

import java.util.List;

/* loaded from: classes3.dex */
public class L {
    public static String a(InterfaceC4954m interfaceC4954m) {
        String string = interfaceC4954m.getClass().getGenericInterfaces()[0].toString();
        return string.startsWith("kotlin.jvm.functions.") ? string.substring(21) : string;
    }

    public static U b(kotlin.reflect.d classifier, List arguments) {
        Intrinsics.checkNotNullParameter(classifier, "classifier");
        Intrinsics.checkNotNullParameter(arguments, "arguments");
        return new U(classifier, arguments, 0);
    }
}
