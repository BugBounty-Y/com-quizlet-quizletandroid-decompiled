package curtains;

import android.util.Log;
import curtains.internal.d;
import java.lang.reflect.Field;
import java.util.ArrayList;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a extends r implements Function0 {
    public static final a a = new a(0);

    /* JADX WARN: Type inference failed for: r2v3, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, kotlin.k] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        Field field;
        curtains.internal.b bVar = new curtains.internal.b();
        Object obj = d.a;
        androidx.credentials.playservices.controllers.BeginSignIn.c swap = new androidx.credentials.playservices.controllers.BeginSignIn.c(bVar, 19);
        Intrinsics.checkNotNullParameter(swap, "swap");
        try {
            Object value = d.b.getValue();
            if (value != null && (field = (Field) d.c.getValue()) != null) {
                Object obj2 = field.get(value);
                if (obj2 == null) {
                    throw new NullPointerException("null cannot be cast to non-null type kotlin.collections.ArrayList<android.view.View> /* = java.util.ArrayList<android.view.View> */");
                }
                field.set(value, swap.invoke((ArrayList) obj2));
                return bVar;
            }
        } catch (Throwable th) {
            Log.w("WindowManagerSpy", th);
        }
        return bVar;
    }
}
