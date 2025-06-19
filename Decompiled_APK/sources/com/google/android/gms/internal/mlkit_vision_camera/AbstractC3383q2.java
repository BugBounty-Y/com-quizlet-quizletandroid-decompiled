package com.google.android.gms.internal.mlkit_vision_camera;

import android.os.Build;
import android.webkit.WebView;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W5;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.q2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3383q2 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 onDismissClick, Function0 onConfirmClick) {
        Intrinsics.checkNotNullParameter(onDismissClick, "onDismissClick");
        Intrinsics.checkNotNullParameter(onConfirmClick, "onConfirmClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-393737122);
        int i2 = (c0814p.h(onDismissClick) ? 4 : 2) | i | (c0814p.h(onConfirmClick) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            qVar = androidx.compose.ui.n.b;
            W5.a(R.string.practice_test_taking_dialog_leave_button, R.string.practice_test_taking_dialog_leave_description, androidx.compose.ui.platform.N.G(qVar, "PracticeTestTakingExitDialog"), onConfirmClick, onDismissClick, null, Integer.valueOf(R.string.practice_test_taking_dialog_leave_title), Integer.valueOf(R.string.practice_test_taking_dialog_cancel_button), c0814p, ((i2 << 6) & 7168) | ((i2 << 12) & 57344), 32);
        }
        androidx.compose.ui.q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.views.composables.k(onDismissClick, onConfirmClick, qVar2, i, 2);
        }
    }

    public static InvocationHandler b() throws NoSuchMethodException, SecurityException {
        ClassLoader classLoader;
        if (Build.VERSION.SDK_INT >= 28) {
            classLoader = androidx.webkit.internal.g.b();
        } else {
            try {
                Method declaredMethod = WebView.class.getDeclaredMethod("getFactory", null);
                declaredMethod.setAccessible(true);
                classLoader = declaredMethod.invoke(null, null).getClass().getClassLoader();
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            } catch (NoSuchMethodException e2) {
                throw new RuntimeException(e2);
            } catch (InvocationTargetException e3) {
                throw new RuntimeException(e3);
            }
        }
        return (InvocationHandler) Class.forName("org.chromium.support_lib_glue.SupportLibReflectionUtil", false, classLoader).getDeclaredMethod("createWebViewProviderFactory", null).invoke(null, null);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:7:0x005a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static org.jsoup.nodes.g c(java.lang.String r9) {
        /*
            Method dump skipped, instructions count: 486
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3383q2.c(java.lang.String):org.jsoup.nodes.g");
    }
}
