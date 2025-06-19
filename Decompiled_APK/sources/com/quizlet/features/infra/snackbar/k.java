package com.quizlet.features.infra.snackbar;

import android.content.res.Resources;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public abstract class k {
    public static final c a;
    public static final d b;
    public static final i c;
    public static final /* synthetic */ k[] d;

    static {
        k kVar = new k() { // from class: com.quizlet.features.infra.snackbar.g
            @Override // com.quizlet.features.infra.snackbar.k
            public final com.google.android.material.snackbar.h a(View view, String message, com.braze.ui.inappmessage.f clickListener) throws Resources.NotFoundException {
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(message, "message");
                Intrinsics.checkNotNullParameter(clickListener, "clickListener");
                b bVar = new b(view);
                bVar.b = message;
                bVar.g = R.dimen.snackbar_text_size;
                bVar.d = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.colorBackgroundSecondary);
                bVar.e = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.textColor);
                bVar.f = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.textColorAccent);
                bVar.h = R.drawable.gray_ripple_unbounded;
                com.google.android.material.snackbar.h hVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(hVarA, "getLightSnackbar(...)");
                return hVarA;
            }
        };
        c cVar = new c();
        a = cVar;
        d dVar = new d();
        b = dVar;
        k kVar2 = new k() { // from class: com.quizlet.features.infra.snackbar.e
            @Override // com.quizlet.features.infra.snackbar.k
            public final com.google.android.material.snackbar.h a(View view, String message, com.braze.ui.inappmessage.f clickListener) {
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(message, "message");
                Intrinsics.checkNotNullParameter(clickListener, "clickListener");
                com.google.android.material.snackbar.h hVarE = I6.e(view, message);
                Intrinsics.checkNotNullExpressionValue(hVarE, "getErrorSnackbar(...)");
                return hVarE;
            }
        };
        k kVar3 = new k() { // from class: com.quizlet.features.infra.snackbar.j
            @Override // com.quizlet.features.infra.snackbar.k
            public final com.google.android.material.snackbar.h a(View view, String message, com.braze.ui.inappmessage.f clickListener) throws Resources.NotFoundException {
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(message, "message");
                Intrinsics.checkNotNullParameter(clickListener, "clickListener");
                b bVar = new b(view);
                bVar.b = message;
                bVar.g = R.dimen.snackbar_text_size;
                bVar.d = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.colorControlSuccess);
                bVar.e = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.textColorInverse);
                bVar.i = R.drawable.ic_sys_check;
                com.google.android.material.snackbar.h hVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(hVarA, "getSuccessSnackbar(...)");
                return hVarA;
            }
        };
        k kVar4 = new k() { // from class: com.quizlet.features.infra.snackbar.f
            @Override // com.quizlet.features.infra.snackbar.k
            public final com.google.android.material.snackbar.h a(View view, String message, com.braze.ui.inappmessage.f clickListener) throws Resources.NotFoundException {
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(message, "message");
                Intrinsics.checkNotNullParameter(clickListener, "clickListener");
                b bVar = new b(view);
                bVar.b = message;
                bVar.g = R.dimen.snackbar_text_size;
                bVar.d = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.colorControlError);
                bVar.e = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.textColorInverse);
                bVar.i = R.drawable.ic_sys_close_x;
                com.google.android.material.snackbar.h hVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(hVarA, "getIncorrectSnackbar(...)");
                return hVarA;
            }
        };
        i iVar = new i();
        c = iVar;
        k[] kVarArr = {kVar, cVar, dVar, kVar2, kVar3, kVar4, iVar, new k() { // from class: com.quizlet.features.infra.snackbar.h
            @Override // com.quizlet.features.infra.snackbar.k
            public final com.google.android.material.snackbar.h a(View view, String message, com.braze.ui.inappmessage.f clickListener) throws Resources.NotFoundException {
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(message, "message");
                Intrinsics.checkNotNullParameter(clickListener, "clickListener");
                b bVar = new b(view);
                bVar.b = message;
                bVar.d = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.SysColorCard);
                bVar.e = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.textColor);
                bVar.c = view.getContext().getString(R.string.settings);
                bVar.j = clickListener;
                com.google.android.material.snackbar.h hVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(hVarA, "getNightThemePreviewSnackbar(...)");
                return hVarA;
            }
        }};
        d = kVarArr;
        AbstractC3328d.f(kVarArr);
    }

    public static k valueOf(String str) {
        return (k) Enum.valueOf(k.class, str);
    }

    public static k[] values() {
        return (k[]) d.clone();
    }

    public abstract com.google.android.material.snackbar.h a(View view, String str, com.braze.ui.inappmessage.f fVar);
}
