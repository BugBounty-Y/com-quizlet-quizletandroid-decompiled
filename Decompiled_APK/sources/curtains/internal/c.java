package curtains.internal;

import android.util.Log;
import java.lang.reflect.Field;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class c extends r implements Function0 {
    public static final c b = new c(0, 0);
    public static final c c = new c(0, 1);
    public static final c d = new c(0, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, int i2) {
        super(i);
        this.a = i2;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v10, types: [java.lang.Object, kotlin.k] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws NoSuchFieldException, SecurityException {
        switch (this.a) {
            case 0:
                Class cls = (Class) d.a.getValue();
                if (cls == null) {
                    return null;
                }
                Field declaredField = cls.getDeclaredField("mViews");
                declaredField.setAccessible(true);
                return declaredField;
            case 1:
                try {
                    return Class.forName("android.view.WindowManagerGlobal");
                } catch (Throwable th) {
                    Log.w("WindowManagerSpy", th);
                    return null;
                }
            default:
                Class cls2 = (Class) d.a.getValue();
                if (cls2 != null) {
                    return cls2.getMethod("getInstance", null).invoke(null, null);
                }
                return null;
        }
    }
}
