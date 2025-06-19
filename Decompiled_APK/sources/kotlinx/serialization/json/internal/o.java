package kotlinx.serialization.json.internal;

import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.collections.M;
import kotlin.collections.V;
import kotlin.collections.b0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.AbstractC5047c0;

/* loaded from: classes3.dex */
public class o extends a {
    public final kotlinx.serialization.json.v f;
    public final SerialDescriptor g;
    public int h;
    public boolean i;

    public /* synthetic */ o(kotlinx.serialization.json.c cVar, kotlinx.serialization.json.v vVar, String str, int i) {
        this(cVar, vVar, (i & 4) != 0 ? null : str, (SerialDescriptor) null);
    }

    @Override // kotlinx.serialization.json.internal.a
    public kotlinx.serialization.json.k E(String tag) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        return (kotlinx.serialization.json.k) V.d(tag, T());
    }

    @Override // kotlinx.serialization.json.internal.a
    public String R(SerialDescriptor descriptor, int i) {
        Object next;
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        kotlinx.serialization.json.c cVar = this.c;
        k.q(descriptor, cVar);
        String strG = descriptor.g(i);
        if (this.e.i && !T().a.keySet().contains(strG)) {
            Intrinsics.checkNotNullParameter(cVar, "<this>");
            Intrinsics.checkNotNullParameter(descriptor, "descriptor");
            Intrinsics.checkNotNullParameter(cVar, "<this>");
            com.quizlet.quizletandroid.ui.login.h hVar = cVar.c;
            l key = k.a;
            com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v defaultValue = new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(15, descriptor, cVar);
            hVar.getClass();
            Intrinsics.checkNotNullParameter(descriptor, "descriptor");
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(defaultValue, "defaultValue");
            Object value = hVar.d(descriptor, key);
            if (value == null) {
                value = defaultValue.invoke();
                Intrinsics.checkNotNullParameter(descriptor, "descriptor");
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(value, "value");
                ConcurrentHashMap concurrentHashMap = (ConcurrentHashMap) hVar.b;
                Object concurrentHashMap2 = concurrentHashMap.get(descriptor);
                if (concurrentHashMap2 == null) {
                    concurrentHashMap2 = new ConcurrentHashMap(2);
                    concurrentHashMap.put(descriptor, concurrentHashMap2);
                }
                ((Map) concurrentHashMap2).put(key, value);
            }
            Map map = (Map) value;
            Iterator it2 = T().a.keySet().iterator();
            while (true) {
                if (!it2.hasNext()) {
                    next = null;
                    break;
                }
                next = it2.next();
                Integer num = (Integer) map.get((String) next);
                if (num != null && num.intValue() == i) {
                    break;
                }
            }
            String str = (String) next;
            if (str != null) {
                return str;
            }
        }
        return strG;
    }

    @Override // kotlinx.serialization.json.internal.a
    /* renamed from: Y, reason: merged with bridge method [inline-methods] */
    public kotlinx.serialization.json.v T() {
        return this.f;
    }

    @Override // kotlinx.serialization.json.internal.a, kotlinx.serialization.encoding.a
    public void b(SerialDescriptor descriptor) {
        Set setF;
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        kotlinx.serialization.json.c cVar = this.c;
        if (k.n(descriptor, cVar) || (descriptor.e() instanceof kotlinx.serialization.descriptors.d)) {
            return;
        }
        k.q(descriptor, cVar);
        if (this.e.i) {
            Intrinsics.checkNotNullParameter(descriptor, "<this>");
            Set setB = AbstractC5047c0.b(descriptor);
            Intrinsics.checkNotNullParameter(cVar, "<this>");
            Map map = (Map) cVar.c.d(descriptor, k.a);
            Set setKeySet = map != null ? map.keySet() : null;
            if (setKeySet == null) {
                setKeySet = M.a;
            }
            setF = b0.f(setB, setKeySet);
        } else {
            Intrinsics.checkNotNullParameter(descriptor, "<this>");
            setF = AbstractC5047c0.b(descriptor);
        }
        for (String str : T().a.keySet()) {
            if (!setF.contains(str) && !Intrinsics.b(str, this.d)) {
                StringBuilder sbY = android.support.v4.media.session.a.y("Encountered an unknown key '", str, "' at element: ");
                sbY.append(V());
                sbY.append("\nUse 'ignoreUnknownKeys = true' in 'Json {}' builder or '@JsonIgnoreUnknownKeys' annotation to ignore unknown keys.\nJSON input: ");
                sbY.append((Object) k.p(-1, T().toString()));
                throw k.c(-1, sbY.toString());
            }
        }
    }

    @Override // kotlinx.serialization.json.internal.a, kotlinx.serialization.encoding.Decoder
    public final kotlinx.serialization.encoding.a c(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        SerialDescriptor serialDescriptor = this.g;
        if (descriptor != serialDescriptor) {
            return super.c(descriptor);
        }
        kotlinx.serialization.json.k kVarF = F();
        String strA = serialDescriptor.a();
        if (kVarF instanceof kotlinx.serialization.json.v) {
            return new o(this.c, (kotlinx.serialization.json.v) kVarF, this.d, serialDescriptor);
        }
        throw k.d(-1, "Expected " + K.a(kotlinx.serialization.json.v.class).f() + ", but had " + K.a(kVarF.getClass()).f() + " as the serialized body of " + strA + " at element: " + V(), kVarF.toString());
    }

    @Override // kotlinx.serialization.json.internal.a, kotlinx.serialization.encoding.Decoder
    public final boolean s() {
        return !this.i && super.s();
    }

    @Override // kotlinx.serialization.encoding.a
    public int t(SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        while (this.h < descriptor.f()) {
            int i = this.h;
            this.h = i + 1;
            String strS = S(descriptor, i);
            int i2 = this.h - 1;
            this.i = false;
            if (!T().containsKey(strS)) {
                boolean z = (this.c.a.e || descriptor.j(i2) || !descriptor.i(i2).c()) ? false : true;
                this.i = z;
                if (z) {
                }
            }
            this.e.getClass();
            return i2;
        }
        return -1;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(kotlinx.serialization.json.c json, kotlinx.serialization.json.v value, String str, SerialDescriptor serialDescriptor) {
        super(json, str);
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(value, "value");
        this.f = value;
        this.g = serialDescriptor;
    }
}
