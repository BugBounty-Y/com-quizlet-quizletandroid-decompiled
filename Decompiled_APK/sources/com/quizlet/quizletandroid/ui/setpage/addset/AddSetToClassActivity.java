package com.quizlet.quizletandroid.ui.setpage.addset;

import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import androidx.activity.v;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.features.emailconfirmation.ui.activities.l;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class AddSetToClassActivity extends l {
    public static final String s;
    public static final int t;
    public static final int u;
    public UserInfoCache p;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e q;
    public final u r;

    static {
        Intrinsics.checkNotNullExpressionValue("AddSetToClassActivity", "getSimpleName(...)");
        s = "AddSetToClassActivity";
        t = R.layout.activity_add_set_to_class;
        u = R.menu.add_set_to_class_menu;
    }

    public AddSetToClassActivity() {
        super(8);
        this.q = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(c.class), new a(this, 1), new a(this, 0), new a(this, 2));
        this.r = kotlin.l.b(new com.quizlet.login.magiclink.ui.e(this, 23));
    }

    @Override // com.quizlet.baseui.base.b
    public final Integer B() {
        return Integer.valueOf(u);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return s;
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        setResult(0);
        super.onBackPressed();
    }

    @Override // com.quizlet.features.emailconfirmation.ui.activities.l, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        super.onCreate(bundle);
        v.b(this, null, 3);
        View viewFindViewById = findViewById(R.id.addClassSetContainer);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        AbstractC3188k6.a(viewFindViewById);
        c cVar = (c) this.q.getValue();
        List setsIds = (List) this.r.getValue();
        cVar.getClass();
        Intrinsics.checkNotNullParameter(setsIds, "setsIds");
        LinkedHashSet linkedHashSet = cVar.f;
        linkedHashSet.clear();
        linkedHashSet.addAll(setsIds);
        setTitle(R.string.class_add);
        LoggedInUserClassSelectionListFragment loggedInUserClassSelectionListFragment = new LoggedInUserClassSelectionListFragment();
        String str = LoggedInUserClassSelectionListFragment.F;
        if (getSupportFragmentManager().E(str) == null) {
            AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
            supportFragmentManager.getClass();
            C1121a c1121a = new C1121a(supportFragmentManager);
            c1121a.l(R.id.addClassContainer, loggedInUserClassSelectionListFragment, str);
            c1121a.g();
        }
    }

    @Override // com.quizlet.baseui.base.b, android.app.Activity
    public final boolean onOptionsItemSelected(MenuItem item) {
        Intrinsics.checkNotNullParameter(item, "item");
        if (item.getItemId() != R.id.menu_add_set_complete) {
            return super.onOptionsItemSelected(item);
        }
        Intent intent = new Intent();
        intent.putExtra("setsIds", CollectionsKt.x0((List) this.r.getValue()));
        ArrayList arrayList = ((c) this.q.getValue()).e.a;
        Intrinsics.checkNotNullExpressionValue(arrayList, "getSelectedItemIds(...)");
        intent.putExtra("selectedClassIds", CollectionsKt.x0(arrayList));
        Unit unit = Unit.a;
        setResult(-1, intent);
        finish();
        return true;
    }

    @Override // android.app.Activity
    public final boolean onPrepareOptionsMenu(Menu menu) {
        Intrinsics.checkNotNullParameter(menu, "menu");
        super.onPrepareOptionsMenu(menu);
        UserInfoCache userInfoCache = this.p;
        if (userInfoCache != null) {
            androidx.work.impl.model.f.b(menu, R.id.menu_add_set_complete, userInfoCache.b());
            return true;
        }
        Intrinsics.m("userInfoCache");
        throw null;
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return t;
    }
}
