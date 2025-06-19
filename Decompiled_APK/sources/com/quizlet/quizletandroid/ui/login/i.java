package com.quizlet.quizletandroid.ui.login;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.util.Log;
import com.facebook.FacebookException;
import com.facebook.internal.C1553h;
import com.facebook.internal.InterfaceC1552g;
import com.facebook.login.LoginClient;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class i implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ FacebookAuthActivity b;

    public /* synthetic */ i(FacebookAuthActivity facebookAuthActivity, int i) {
        this.a = i;
        this.b = facebookAuthActivity;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                FacebookAuthActivity activity = this.b;
                final com.facebook.login.B b = (com.facebook.login.B) obj;
                int i = FacebookAuthActivity.j;
                List<String> list = com.quizlet.generated.sharedconfig.b.a;
                b.getClass();
                Intrinsics.checkNotNullParameter(activity, "activity");
                if (list != null) {
                    for (String str : list) {
                        com.facebook.login.y yVar = com.facebook.login.B.b;
                        if (com.facebook.login.y.b(str)) {
                            throw new FacebookException(android.support.v4.media.session.a.B("Cannot pass a publish or manage permission (", str, ") to a request for read authorization"));
                        }
                    }
                }
                com.quizlet.data.repository.folderwithcreator.e loginConfig = new com.quizlet.data.repository.folderwithcreator.e((Collection) list);
                Intrinsics.checkNotNullParameter(activity, "activity");
                Intrinsics.checkNotNullParameter(loginConfig, "loginConfig");
                Log.w(com.facebook.login.B.d, "You're calling logging in Facebook with an activity supports androidx activity result APIs. Please follow our document to upgrade to new APIs to avoid overriding onActivityResult().");
                LoginClient.Request requestA = com.facebook.login.B.a(loginConfig);
                Intrinsics.checkNotNullParameter(activity, "activity");
                com.facebook.login.B.d(activity, requestA);
                com.google.mlkit.common.internal.model.a aVar = C1553h.b;
                int iA = assistantMode.refactored.a.a(1);
                InterfaceC1552g callback = new InterfaceC1552g() { // from class: com.facebook.login.x
                    @Override // com.facebook.internal.InterfaceC1552g
                    public final void a(int i2, Intent intent) {
                        B this$0 = b;
                        Intrinsics.checkNotNullParameter(this$0, "this$0");
                        this$0.e(i2, intent, null);
                    }
                };
                synchronized (aVar) {
                    Intrinsics.checkNotNullParameter(callback, "callback");
                    HashMap map = C1553h.c;
                    if (!map.containsKey(Integer.valueOf(iA))) {
                        map.put(Integer.valueOf(iA), callback);
                    }
                }
                Intent intent = com.facebook.login.B.b(requestA);
                if (com.facebook.o.a().getPackageManager().resolveActivity(intent, 0) != null) {
                    try {
                        int iA2 = assistantMode.refactored.a.a(1);
                        Intrinsics.checkNotNullParameter(intent, "intent");
                        activity.startActivityForResult(intent, iA2);
                        return Unit.a;
                    } catch (ActivityNotFoundException unused) {
                    }
                }
                FacebookException facebookException = new FacebookException("Log in attempt failed: FacebookActivity could not be started. Please make sure you added FacebookActivity to the AndroidManifest.");
                com.facebook.login.B.c(activity, com.facebook.login.q.ERROR, null, facebookException, false, requestA);
                throw facebookException;
            default:
                FacebookAuthActivity facebookAuthActivity = this.b;
                ((com.facebook.login.B) obj).f(facebookAuthActivity.h, new com.quizlet.quizletandroid.k(facebookAuthActivity, 6));
                return Unit.a;
        }
    }
}
