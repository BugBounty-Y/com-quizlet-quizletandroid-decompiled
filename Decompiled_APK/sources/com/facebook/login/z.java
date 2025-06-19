package com.facebook.login;

import android.content.Context;
import android.content.Intent;
import com.facebook.FacebookException;
import com.facebook.internal.C1553h;
import com.facebook.login.LoginClient;
import java.util.Collection;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class z extends androidx.activity.result.contract.a {
    public final com.facebook.j a;
    public final /* synthetic */ B b;

    public z(B b, com.facebook.j jVar) {
        this.b = b;
        this.a = jVar;
    }

    @Override // androidx.activity.result.contract.a
    public final Intent a(Context context, Object obj) {
        Collection permissions = (Collection) obj;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        LoginClient.Request requestA = B.a(new com.quizlet.data.repository.folderwithcreator.e(permissions));
        B.d(context, requestA);
        Intent intentB = B.b(requestA);
        if (com.facebook.o.a().getPackageManager().resolveActivity(intentB, 0) != null) {
            return intentB;
        }
        FacebookException facebookException = new FacebookException("Log in attempt failed: FacebookActivity could not be started. Please make sure you added FacebookActivity to the AndroidManifest.");
        B.c(context, q.ERROR, null, facebookException, false, requestA);
        throw facebookException;
    }

    @Override // androidx.activity.result.contract.a
    public final Object c(int i, Intent intent) {
        this.b.e(i, intent, null);
        int iA = assistantMode.refactored.a.a(1);
        com.facebook.j jVar = this.a;
        if (jVar != null) {
            ((C1553h) jVar).a(iA, i, intent);
        }
        return new com.facebook.i(iA, i, intent);
    }
}
