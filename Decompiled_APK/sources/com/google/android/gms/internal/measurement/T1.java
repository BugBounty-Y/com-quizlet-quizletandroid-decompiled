package com.google.android.gms.internal.measurement;

import androidx.recyclerview.widget.C1372j;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class T1 {
    public static final /* synthetic */ int a = 0;

    public static int a(int i, int i2, boolean z) {
        int i3 = z ? ((i2 - i) + 360) % 360 : (i2 + i) % 360;
        if (AbstractC3053s1.f(2, "CameraOrientationUtil")) {
            StringBuilder sbW = android.support.v4.media.session.a.w("getRelativeImageRotation: destRotationDegrees=", i, ", sourceRotationDegrees=", ", isOppositeFacing=", i2);
            sbW.append(z);
            sbW.append(", result=");
            sbW.append(i3);
            AbstractC3053s1.f(3, "CameraOrientationUtil");
        }
        return i3;
    }

    public static int b(int i) {
        if (i == 0) {
            return 0;
        }
        if (i == 1) {
            return 90;
        }
        if (i == 2) {
            return SubsamplingScaleImageView.ORIENTATION_180;
        }
        if (i == 3) {
            return SubsamplingScaleImageView.ORIENTATION_270;
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Unsupported surface rotation: "));
    }

    public static final okhttp3.s c(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        C1372j c1372j = new C1372j();
        c1372j.l(null, str);
        okhttp3.s sVarD = c1372j.d();
        if (sVarD.j) {
            Intrinsics.b(sVarD.d, "quizlet.com");
        }
        return sVarD;
    }

    public static Q1 d() {
        String strI;
        ClassLoader classLoader = T1.class.getClassLoader();
        if (Q1.class.equals(Q1.class)) {
            strI = "com.google.protobuf.BlazeGeneratedExtensionRegistryLiteLoader";
        } else {
            if (!Q1.class.getPackage().equals(T1.class.getPackage())) {
                throw new IllegalArgumentException(Q1.class.getName());
            }
            strI = androidx.compose.ui.node.B.i(Q1.class.getPackage().getName(), ".BlazeGenerated", Q1.class.getSimpleName(), "Loader");
        }
        try {
            try {
                try {
                    android.support.v4.media.session.a.A(Class.forName(strI, true, classLoader).getConstructor(null).newInstance(null));
                    throw null;
                } catch (InstantiationException e) {
                    throw new IllegalStateException(e);
                } catch (InvocationTargetException e2) {
                    throw new IllegalStateException(e2);
                }
            } catch (IllegalAccessException e3) {
                throw new IllegalStateException(e3);
            } catch (NoSuchMethodException e4) {
                throw new IllegalStateException(e4);
            }
        } catch (ClassNotFoundException unused) {
            try {
                Iterator it2 = Arrays.asList(new T1[0]).iterator();
                ArrayList arrayList = new ArrayList();
                while (it2.hasNext()) {
                    try {
                        if (it2.next() == null) {
                            throw null;
                        }
                        throw new ClassCastException();
                    } catch (ServiceConfigurationError e5) {
                        Logger.getLogger(P1.class.getName()).logp(Level.SEVERE, "com.google.protobuf.GeneratedExtensionRegistryLoader", "load", "Unable to load ".concat(Q1.class.getSimpleName()), (Throwable) e5);
                    }
                }
                if (arrayList.size() == 1) {
                    return (Q1) arrayList.get(0);
                }
                if (arrayList.size() == 0) {
                    return null;
                }
                try {
                    return (Q1) Q1.class.getMethod("combine", Collection.class).invoke(null, arrayList);
                } catch (IllegalAccessException e6) {
                    throw new IllegalStateException(e6);
                } catch (NoSuchMethodException e7) {
                    throw new IllegalStateException(e7);
                } catch (InvocationTargetException e8) {
                    throw new IllegalStateException(e8);
                }
            } catch (Throwable th) {
                throw new ServiceConfigurationError(th.getMessage(), th);
            }
        }
    }
}
