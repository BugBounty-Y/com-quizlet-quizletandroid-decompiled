package androidx.constraintlayout.motion.utils;

import android.util.Log;
import android.view.View;
import androidx.constraintlayout.motion.widget.r;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/* loaded from: classes.dex */
public final class o extends p {
    public boolean j;

    @Override // androidx.constraintlayout.motion.utils.p
    public final boolean c(float f, long j, View view, androidx.constraintlayout.core.motion.utils.e eVar) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Method method;
        o oVar;
        float fB;
        if (view instanceof r) {
            float fB2 = b(f, j, view, eVar);
            oVar = this;
            ((r) view).setProgress(fB2);
        } else {
            if (this.j) {
                return false;
            }
            try {
                method = view.getClass().getMethod("setProgress", Float.TYPE);
            } catch (NoSuchMethodException unused) {
                this.j = true;
                method = null;
            }
            if (method != null) {
                try {
                    fB = b(f, j, view, eVar);
                    oVar = this;
                } catch (IllegalAccessException e) {
                    e = e;
                    oVar = this;
                } catch (InvocationTargetException e2) {
                    e = e2;
                    oVar = this;
                }
                try {
                    method.invoke(view, Float.valueOf(fB));
                } catch (IllegalAccessException e3) {
                    e = e3;
                    Log.e("ViewTimeCycle", "unable to setProgress", e);
                    return oVar.g;
                } catch (InvocationTargetException e4) {
                    e = e4;
                    Log.e("ViewTimeCycle", "unable to setProgress", e);
                    return oVar.g;
                }
            } else {
                oVar = this;
            }
        }
        return oVar.g;
    }
}
