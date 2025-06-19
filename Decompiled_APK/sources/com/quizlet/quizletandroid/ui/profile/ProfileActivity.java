package com.quizlet.quizletandroid.ui.profile;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3197l6;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ProfileActivity extends com.quizlet.features.emailconfirmation.ui.activities.l {
    public static final b p = new b();
    public static final String q;

    static {
        Intrinsics.checkNotNullExpressionValue("ProfileActivity", "getSimpleName(...)");
        q = "ProfileActivity";
    }

    public ProfileActivity() {
        super(7);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return q;
    }

    @Override // com.quizlet.baseui.base.b
    public final boolean H() {
        return false;
    }

    public final void P(Intent intent, boolean z) {
        Bundle extras = intent.getExtras();
        if (extras == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        long j = extras.getLong("userId");
        Bundle extras2 = intent.getExtras();
        if (extras2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        int i = extras2.getInt("jumpToTab", -1);
        Bundle extras3 = intent.getExtras();
        if (extras3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        String string = extras3.getString("badgeId");
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        String str = ProfileFragment.x;
        Fragment fragmentE = supportFragmentManager.E(str);
        ProfileFragment profileFragment = fragmentE instanceof ProfileFragment ? (ProfileFragment) fragmentE : null;
        Bundle bundle = new Bundle();
        bundle.putLong("userId", j);
        bundle.putInt("jumpToTab", i);
        bundle.putBoolean("fromActivityParent", true);
        bundle.putString("badgeId", string);
        ProfileFragment profileFragment2 = new ProfileFragment();
        profileFragment2.setArguments(bundle);
        AbstractC1136h0 supportFragmentManager2 = getSupportFragmentManager();
        supportFragmentManager2.getClass();
        C1121a c1121a = new C1121a(supportFragmentManager2);
        Intrinsics.checkNotNullExpressionValue(c1121a, "beginTransaction(...)");
        if (profileFragment == null || z) {
            c1121a.l(R.id.profileFragmentContainer, profileFragment2, str);
            c1121a.g();
        }
    }

    @Override // com.quizlet.features.emailconfirmation.ui.activities.l, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        super.onCreate(bundle);
        androidx.activity.v.b(this, null, 3);
        View viewFindViewById = findViewById(R.id.profileFragmentContainer);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        com.quizlet.infra.legacysyncengine.models.serializers.a aVar = new com.quizlet.infra.legacysyncengine.models.serializers.a(23);
        WeakHashMap weakHashMap = V.a;
        L.m(viewFindViewById, aVar);
        AbstractC3197l6.b(this, "userId");
        Intent intent = getIntent();
        Intrinsics.checkNotNullExpressionValue(intent, "getIntent(...)");
        P(intent, false);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onNewIntent(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.onNewIntent(intent);
        P(intent, true);
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return R.layout.activity_profile;
    }
}
