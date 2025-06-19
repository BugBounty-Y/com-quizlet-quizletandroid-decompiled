package retrofit2;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

/* loaded from: classes3.dex */
public final class G extends C5176a {
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ G(int i) {
        super(7);
        this.h = i;
    }

    @Override // retrofit2.C5176a
    public String c(Method method, int i) {
        switch (this.h) {
            case 1:
                Parameter parameter = method.getParameters()[i];
                if (!parameter.isNamePresent()) {
                    break;
                } else {
                    break;
                }
        }
        return super.c(method, i);
    }

    @Override // retrofit2.C5176a
    public final Object d(Class cls, Object obj, Method method, Object[] objArr) {
        switch (this.h) {
        }
        return S.l(cls, obj, method, objArr);
    }

    @Override // retrofit2.C5176a
    public final boolean e(Method method) {
        switch (this.h) {
        }
        return method.isDefault();
    }
}
