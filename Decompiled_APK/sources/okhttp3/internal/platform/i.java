package okhttp3.internal.platform;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements InvocationHandler {
    public final ArrayList a;
    public boolean b;
    public String c;

    public i(ArrayList protocols) {
        Intrinsics.checkNotNullParameter(protocols, "protocols");
        this.a = protocols;
    }

    @Override // java.lang.reflect.InvocationHandler
    public final Object invoke(Object proxy, Method method, Object[] objArr) {
        Intrinsics.checkNotNullParameter(proxy, "proxy");
        Intrinsics.checkNotNullParameter(method, "method");
        if (objArr == null) {
            objArr = new Object[0];
        }
        String name = method.getName();
        Class<?> returnType = method.getReturnType();
        if (Intrinsics.b(name, "supports") && Intrinsics.b(Boolean.TYPE, returnType)) {
            return Boolean.TRUE;
        }
        if (Intrinsics.b(name, "unsupported") && Intrinsics.b(Void.TYPE, returnType)) {
            this.b = true;
            return null;
        }
        boolean zB = Intrinsics.b(name, "protocols");
        ArrayList arrayList = this.a;
        if (zB && objArr.length == 0) {
            return arrayList;
        }
        if ((Intrinsics.b(name, "selectProtocol") || Intrinsics.b(name, "select")) && String.class.equals(returnType) && objArr.length == 1) {
            Object obj = objArr[0];
            if (obj instanceof List) {
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.List<*>");
                List list = (List) obj;
                int size = list.size();
                if (size >= 0) {
                    int i = 0;
                    while (true) {
                        Object obj2 = list.get(i);
                        Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.String");
                        String str = (String) obj2;
                        if (!arrayList.contains(str)) {
                            if (i == size) {
                                break;
                            }
                            i++;
                        } else {
                            this.c = str;
                            return str;
                        }
                    }
                }
                String str2 = (String) arrayList.get(0);
                this.c = str2;
                return str2;
            }
        }
        if ((!Intrinsics.b(name, "protocolSelected") && !Intrinsics.b(name, "selected")) || objArr.length != 1) {
            return method.invoke(this, Arrays.copyOf(objArr, objArr.length));
        }
        Object obj3 = objArr[0];
        Intrinsics.e(obj3, "null cannot be cast to non-null type kotlin.String");
        this.c = (String) obj3;
        return null;
    }
}
