package com.quizlet.quizletandroid.ui.group;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import androidx.activity.v;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.emailconfirmation.ui.activities.l;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class GroupActivity extends l {
    public static final String u;
    public static final int v;
    public EventLogger p;
    public com.quizlet.utmhelper.c q;
    public final u r;
    public final u s;
    public final u t;

    static {
        Intrinsics.checkNotNullExpressionValue("GroupActivity", "getSimpleName(...)");
        u = "GroupActivity";
        v = R.layout.activity_class;
    }

    public GroupActivity() {
        super(4);
        final int i = 0;
        this.r = kotlin.l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.group.a
            public final /* synthetic */ GroupActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                GroupActivity groupActivity = this.b;
                switch (i) {
                    case 0:
                        String str = GroupActivity.u;
                        return Long.valueOf(groupActivity.getIntent().getLongExtra(DBGroupMembershipFields.Names.CLASS_ID, 0L));
                    case 1:
                        String str2 = GroupActivity.u;
                        return groupActivity.getIntent().getStringExtra("autoJoinCode");
                    default:
                        String str3 = GroupActivity.u;
                        return Boolean.valueOf(groupActivity.getIntent().getBooleanExtra("shouldShowJoinButton", false));
                }
            }
        });
        final int i2 = 1;
        this.s = kotlin.l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.group.a
            public final /* synthetic */ GroupActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                GroupActivity groupActivity = this.b;
                switch (i2) {
                    case 0:
                        String str = GroupActivity.u;
                        return Long.valueOf(groupActivity.getIntent().getLongExtra(DBGroupMembershipFields.Names.CLASS_ID, 0L));
                    case 1:
                        String str2 = GroupActivity.u;
                        return groupActivity.getIntent().getStringExtra("autoJoinCode");
                    default:
                        String str3 = GroupActivity.u;
                        return Boolean.valueOf(groupActivity.getIntent().getBooleanExtra("shouldShowJoinButton", false));
                }
            }
        });
        final int i3 = 2;
        this.t = kotlin.l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.group.a
            public final /* synthetic */ GroupActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                GroupActivity groupActivity = this.b;
                switch (i3) {
                    case 0:
                        String str = GroupActivity.u;
                        return Long.valueOf(groupActivity.getIntent().getLongExtra(DBGroupMembershipFields.Names.CLASS_ID, 0L));
                    case 1:
                        String str2 = GroupActivity.u;
                        return groupActivity.getIntent().getStringExtra("autoJoinCode");
                    default:
                        String str3 = GroupActivity.u;
                        return Boolean.valueOf(groupActivity.getIntent().getBooleanExtra("shouldShowJoinButton", false));
                }
            }
        });
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return u;
    }

    @Override // com.quizlet.features.emailconfirmation.ui.activities.l, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) throws NumberFormatException {
        long jLongValue;
        super.onCreate(bundle);
        v.b(this, null, 3);
        Intent intent = getIntent();
        Intrinsics.checkNotNullExpressionValue(intent, "getIntent(...)");
        u uVar = this.r;
        long jLongValue2 = ((Number) uVar.getValue()).longValue();
        u uVar2 = this.t;
        String str = u;
        if (jLongValue2 != 0) {
            Uri data = intent.getData();
            if (((Boolean) uVar2.getValue()).booleanValue() && data != null) {
                EventLogger eventLogger = this.p;
                if (eventLogger == null) {
                    Intrinsics.m("eventLogger");
                    throw null;
                }
                com.quizlet.quizletandroid.util.links.a.a(eventLogger, data, str);
                EventLogger eventLogger2 = this.p;
                if (eventLogger2 == null) {
                    Intrinsics.m("eventLogger");
                    throw null;
                }
                com.quizlet.utmhelper.c cVar = this.q;
                if (cVar == null) {
                    Intrinsics.m("jsUtmHelper");
                    throw null;
                }
                com.quizlet.quizletandroid.util.links.a.b(eventLogger2, data, cVar, Long.valueOf(((Number) uVar.getValue()).longValue()), null, 4);
            }
            jLongValue = ((Number) uVar.getValue()).longValue();
        } else {
            if (!"android.intent.action.VIEW".equals(intent.getAction()) || intent.getData() == null) {
                timber.log.c.a.e(new RuntimeException("No class id or code provided"));
            } else {
                Uri data2 = intent.getData();
                EventLogger eventLogger3 = this.p;
                if (eventLogger3 == null) {
                    Intrinsics.m("eventLogger");
                    throw null;
                }
                com.quizlet.quizletandroid.util.links.a.a(eventLogger3, data2, str);
                List<String> pathSegments = data2.getPathSegments();
                if (pathSegments == null) {
                    pathSegments = K.a;
                }
                if (pathSegments.isEmpty()) {
                    timber.log.c.a.e(new RuntimeException(android.support.v4.media.session.a.h(data2, "Could not parse uri: ")));
                } else if (D.l(pathSegments.get(0), AssociationNames.CLASS, true)) {
                    try {
                        long j = Long.parseLong(pathSegments.get(1));
                        EventLogger eventLogger4 = this.p;
                        if (eventLogger4 == null) {
                            Intrinsics.m("eventLogger");
                            throw null;
                        }
                        com.quizlet.utmhelper.c cVar2 = this.q;
                        if (cVar2 == null) {
                            Intrinsics.m("jsUtmHelper");
                            throw null;
                        }
                        com.quizlet.quizletandroid.util.links.a.b(eventLogger4, data2, cVar2, Long.valueOf(j), null, 4);
                        jLongValue = j;
                    } catch (IndexOutOfBoundsException e) {
                        timber.log.c.a.e(e);
                    } catch (NumberFormatException e2) {
                        timber.log.c.a.e(e2);
                    }
                }
            }
            jLongValue = 0;
        }
        if (jLongValue == 0) {
            finish();
            return;
        }
        if (getSupportFragmentManager().D(R.id.groupFragmentContainer) == null) {
            String str2 = GroupFragment.M;
            String str3 = (String) this.s.getValue();
            boolean zBooleanValue = ((Boolean) uVar2.getValue()).booleanValue();
            GroupFragment groupFragment = new GroupFragment();
            Bundle bundle2 = new Bundle();
            bundle2.putLong("KEY_GROUP_CLASS_ID", jLongValue);
            bundle2.putString("autoJoinCode", str3);
            bundle2.putBoolean("shouldShowJoinButton", zBooleanValue);
            groupFragment.setArguments(bundle2);
            AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
            supportFragmentManager.getClass();
            C1121a c1121a = new C1121a(supportFragmentManager);
            c1121a.l(R.id.groupFragmentContainer, groupFragment, GroupFragment.M);
            c1121a.g();
        }
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return v;
    }
}
