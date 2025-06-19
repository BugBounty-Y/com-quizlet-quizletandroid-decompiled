package androidx.webkit.internal;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3383q2;
import java.lang.reflect.InvocationTargetException;
import org.chromium.support_lib_boundary.WebViewProviderFactoryBoundaryInterface;

/* loaded from: classes.dex */
public abstract class u {
    public static final v a;

    static {
        v lVar;
        try {
            lVar = new com.quizlet.data.repository.school.membership.a((WebViewProviderFactoryBoundaryInterface) org.chromium.support_lib_boundary.util.a.f(WebViewProviderFactoryBoundaryInterface.class, AbstractC3383q2.b()), 13);
        } catch (ClassNotFoundException unused) {
            lVar = new l();
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e2) {
            throw new RuntimeException(e2);
        } catch (InvocationTargetException e3) {
            throw new RuntimeException(e3);
        }
        a = lVar;
    }
}
