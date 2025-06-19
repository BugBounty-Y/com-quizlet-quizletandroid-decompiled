package com.quizlet.features.infra.photo;

import android.content.Intent;
import androidx.activity.result.ActivityResult;
import com.quizlet.features.infra.snackbar.m;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.profile.ProfileFragment;
import com.quizlet.quizletandroid.ui.profile.data.h;
import com.quizlet.qutils.string.e;
import com.quizlet.qutils.string.f;
import com.quizlet.qutils.string.g;
import kotlin.InterfaceC4938g;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.InterfaceC4953l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements androidx.activity.result.a, InterfaceC4953l {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ Object b;

    public a(ProfileFragment profileFragment) {
        this.b = profileFragment;
    }

    @Override // androidx.activity.result.a
    public final void a(Object obj) {
        g fVar;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                ((Function1) obj2).invoke(obj);
                break;
            default:
                ActivityResult p0 = (ActivityResult) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                String str = ProfileFragment.x;
                ProfileFragment profileFragment = (ProfileFragment) obj2;
                int i = p0.a;
                if (i == -1) {
                    h hVarX = profileFragment.X();
                    if (hVarX.C(hVarX.n)) {
                        hVarX.D();
                        Object[] args = new Object[0];
                        Intrinsics.checkNotNullParameter(args, "args");
                        hVarX.m.j(new m(new f(R.string.user_settings_profile_image_changed, C4933y.P(args))));
                        break;
                    }
                } else if (i == 2) {
                    Intent intent = p0.b;
                    String string = intent != null ? intent.getStringExtra("EXTRA_ERROR") : null;
                    h hVarX2 = profileFragment.X();
                    hVarX2.getClass();
                    if (string != null) {
                        Intrinsics.checkNotNullParameter(string, "string");
                        fVar = new e(string);
                    } else {
                        Object[] args2 = new Object[0];
                        Intrinsics.checkNotNullParameter(args2, "args");
                        fVar = new f(R.string.user_settings_profile_image_upload_error, C4933y.P(args2));
                    }
                    hVarX2.m.j(new m(fVar));
                    break;
                }
                break;
        }
    }

    public final boolean equals(Object obj) {
        switch (this.a) {
            case 0:
                if ((obj instanceof androidx.activity.result.a) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            default:
                if ((obj instanceof androidx.activity.result.a) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
        }
        return Intrinsics.b(getFunctionDelegate(), ((InterfaceC4953l) obj).getFunctionDelegate());
    }

    @Override // kotlin.jvm.internal.InterfaceC4953l
    public final InterfaceC4938g getFunctionDelegate() {
        switch (this.a) {
            case 0:
                return (Function1) this.b;
            default:
                return new C4956o(1, 0, ProfileFragment.class, (ProfileFragment) this.b, "onProfileImageResultReceived", "onProfileImageResultReceived(Landroidx/activity/result/ActivityResult;)V");
        }
    }

    public final int hashCode() {
        switch (this.a) {
        }
        return getFunctionDelegate().hashCode();
    }

    public a(Function1 function) {
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }
}
