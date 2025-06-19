package androidx.navigation;

import com.google.android.gms.internal.measurement.C3052s0;
import com.google.android.gms.internal.measurement.C3067v0;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.google.android.gms.internal.mlkit_vision_camera.P1;
import com.google.android.gms.internal.mlkit_vision_camera.S1;
import java.io.Serializable;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;

/* loaded from: classes.dex */
public abstract class C {
    public final String a;
    public final int b;
    public Object c;
    public Serializable d;
    public Serializable e;
    public Serializable f;

    public C(String str, int i) {
        this.a = str;
        this.b = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0107  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Boolean f(java.math.BigDecimal r8, com.google.android.gms.internal.measurement.C3052s0 r9, double r10) {
        /*
            Method dump skipped, instructions count: 280
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.C.f(java.math.BigDecimal, com.google.android.gms.internal.measurement.s0, double):java.lang.Boolean");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public static Boolean g(String str, C3067v0 c3067v0, com.google.android.gms.measurement.internal.I i) {
        List listQ;
        com.google.android.gms.common.internal.u.h(c3067v0);
        if (str != null && c3067v0.u() && c3067v0.v() != 1 && (c3067v0.v() != 7 ? c3067v0.t() : c3067v0.n() != 0)) {
            int iV = c3067v0.v();
            boolean zR = c3067v0.r();
            String strP = (zR || iV == 2 || iV == 7) ? c3067v0.p() : c3067v0.p().toUpperCase(Locale.ENGLISH);
            if (c3067v0.n() == 0) {
                listQ = null;
            } else {
                listQ = c3067v0.q();
                if (!zR) {
                    ArrayList arrayList = new ArrayList(listQ.size());
                    Iterator it2 = listQ.iterator();
                    while (it2.hasNext()) {
                        arrayList.add(((String) it2.next()).toUpperCase(Locale.ENGLISH));
                    }
                    listQ = Collections.unmodifiableList(arrayList);
                }
            }
            String str2 = iV == 2 ? strP : null;
            if (iV != 7 ? strP != null : listQ != null && !listQ.isEmpty()) {
                if (!zR && iV != 2) {
                    str = str.toUpperCase(Locale.ENGLISH);
                }
                switch (iV - 1) {
                    case 1:
                        if (str2 != null) {
                            try {
                                return Boolean.valueOf(Pattern.compile(str2, true != zR ? 66 : 0).matcher(str).matches());
                            } catch (PatternSyntaxException unused) {
                                if (i != null) {
                                    i.j.g("Invalid regular expression in REGEXP audience filter. expression", str2);
                                    break;
                                }
                            }
                        }
                        break;
                    case 2:
                        return Boolean.valueOf(str.startsWith(strP));
                    case 3:
                        return Boolean.valueOf(str.endsWith(strP));
                    case 4:
                        return Boolean.valueOf(str.contains(strP));
                    case 5:
                        return Boolean.valueOf(str.equals(strP));
                    case 6:
                        if (listQ != null) {
                            return Boolean.valueOf(listQ.contains(str));
                        }
                        break;
                }
            }
        }
        return null;
    }

    public static Boolean h(long j, C3052s0 c3052s0) {
        try {
            return f(new BigDecimal(j), c3052s0, 0.0d);
        } catch (NumberFormatException unused) {
            return null;
        }
    }

    public static Boolean i(Boolean bool, boolean z) {
        if (bool == null) {
            return null;
        }
        return Boolean.valueOf(bool.booleanValue() != z);
    }

    public B a() {
        androidx.navigation.internal.m mVar;
        B b = b();
        b.getClass();
        Iterator it2 = ((LinkedHashMap) this.d).entrySet().iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            mVar = b.b;
            if (!zHasNext) {
                break;
            }
            Map.Entry entry = (Map.Entry) it2.next();
            String argumentName = (String) entry.getKey();
            C1289k argument = (C1289k) entry.getValue();
            Intrinsics.checkNotNullParameter(argumentName, "argumentName");
            Intrinsics.checkNotNullParameter(argument, "argument");
            mVar.getClass();
            Intrinsics.checkNotNullParameter(argumentName, "argumentName");
            Intrinsics.checkNotNullParameter(argument, "argument");
            ((LinkedHashMap) mVar.e).put(argumentName, argument);
        }
        Iterator it3 = ((ArrayList) this.f).iterator();
        while (it3.hasNext()) {
            b.a((C1301x) it3.next());
        }
        for (Map.Entry entry2 : ((LinkedHashMap) this.e).entrySet()) {
            int iIntValue = ((Number) entry2.getKey()).intValue();
            if (entry2.getValue() != null) {
                throw new ClassCastException();
            }
            Intrinsics.checkNotNullParameter(null, "action");
            if (b instanceof C1266b) {
                throw new UnsupportedOperationException("Cannot add action " + iIntValue + " to " + b + " as it does not support actions, indicating that it is a terminal destination in your navigation graph and will never trigger actions.");
            }
            if (iIntValue == 0) {
                throw new IllegalArgumentException("Cannot have an action with actionId 0");
            }
            b.d.f(iIntValue, null);
        }
        String str = this.a;
        if (str != null) {
            b.j(str);
        }
        int i = this.b;
        if (i != -1) {
            mVar.c = i;
        }
        return b;
    }

    public B b() {
        return ((W) this.c).a();
    }

    public abstract int c();

    public abstract boolean d();

    public abstract boolean e();

    public C(W navigator, int i, String str) {
        Intrinsics.checkNotNullParameter(navigator, "navigator");
        this.c = navigator;
        this.b = i;
        this.a = str;
        this.d = new LinkedHashMap();
        this.f = new ArrayList();
        this.e = new LinkedHashMap();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C(W navigator, String str) {
        this(navigator, -1, str);
        Intrinsics.checkNotNullParameter(navigator, "navigator");
    }

    public C(W navigator, C4950i c4950i, kotlin.collections.L typeMap) throws ClassNotFoundException {
        Intrinsics.checkNotNullParameter(navigator, "navigator");
        Intrinsics.checkNotNullParameter(typeMap, "typeMap");
        int iB = c4950i != null ? androidx.navigation.serialization.d.b(P1.e(c4950i)) : -1;
        if (c4950i != null) {
            KSerializer kSerializerE = P1.e(c4950i);
            Intrinsics.checkNotNullParameter(kSerializerE, "<this>");
            Intrinsics.checkNotNullParameter(typeMap, "typeMap");
            if (kSerializerE instanceof kotlinx.serialization.c) {
                StringBuilder sb = new StringBuilder("Cannot generate route pattern from polymorphic class ");
                kotlin.reflect.c cVarB = S1.b(((kotlinx.serialization.c) kSerializerE).getDescriptor());
                throw new IllegalArgumentException(android.support.v4.media.session.a.t(sb, cVarB != null ? ((C4950i) cVarB).f() : null, ". Routes can only be generated from concrete classes or objects."));
            }
            com.quizlet.data.repository.progress.b bVar = new com.quizlet.data.repository.progress.b(kSerializerE);
            androidx.navigation.serialization.i iVar = new androidx.navigation.serialization.i(bVar, 0);
            int iF = kSerializerE.getDescriptor().f();
            for (int i = 0; i < iF; i++) {
                String strG = kSerializerE.getDescriptor().g(i);
                S sA = androidx.navigation.serialization.d.a(kSerializerE.getDescriptor().i(i), typeMap);
                if (sA != null) {
                    iVar.invoke(Integer.valueOf(i), strG, sA);
                } else {
                    String strA = kSerializerE.getDescriptor().i(i).a();
                    String strA2 = kSerializerE.getDescriptor().a();
                    typeMap.getClass();
                    throw new IllegalArgumentException(androidx.navigation.serialization.d.g(strG, strA, strA2, "{}"));
                }
            }
            str = ((String) bVar.b) + ((String) bVar.c) + ((String) bVar.d);
        }
        this(navigator, iB, str);
        if (c4950i != null) {
            KSerializer kSerializerE2 = P1.e(c4950i);
            Intrinsics.checkNotNullParameter(kSerializerE2, "<this>");
            Intrinsics.checkNotNullParameter(typeMap, "typeMap");
            if (!(kSerializerE2 instanceof kotlinx.serialization.c)) {
                int iF2 = kSerializerE2.getDescriptor().f();
                ArrayList arrayList = new ArrayList(iF2);
                int i2 = 0;
                while (i2 < iF2) {
                    String strG2 = kSerializerE2.getDescriptor().g(i2);
                    kotlin.collections.L l = typeMap;
                    arrayList.add(D1.b(strG2, new androidx.navigation.serialization.k(i2, 0, kSerializerE2, l, strG2)));
                    i2++;
                    typeMap = l;
                }
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    C1287i c1287i = (C1287i) it2.next();
                    ((LinkedHashMap) this.d).put(c1287i.a, c1287i.b);
                }
                return;
            }
            throw new IllegalArgumentException("Cannot generate NavArguments for polymorphic serializer " + kSerializerE2 + ". Arguments can only be generated from concrete classes or objects.");
        }
    }
}
