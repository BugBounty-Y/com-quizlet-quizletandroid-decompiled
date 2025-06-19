package com.quizlet.quizletandroid.ui.usersettings.fragments;

import android.net.Uri;
import android.text.TextUtils;
import com.quizlet.api.model.ProfileImage;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ChangeProfileImageFragment b;

    public /* synthetic */ a(ChangeProfileImageFragment changeProfileImageFragment, int i) {
        this.a = i;
        this.b = changeProfileImageFragment;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 0;
        ChangeProfileImageFragment changeProfileImageFragment = this.b;
        switch (this.a) {
            case 0:
                Uri uri = (Uri) obj;
                String str = ChangeProfileImageFragment.w;
                if (uri != null) {
                    try {
                        changeProfileImageFragment.U(uri);
                    } catch (Exception e) {
                        timber.log.c.a.q(e, "Fail to crop image on ChangeProfileImageFragment", new Object[0]);
                    }
                }
                break;
            case 1:
                List it2 = (List) obj;
                String str2 = ChangeProfileImageFragment.w;
                Intrinsics.checkNotNullParameter(it2, "it");
                com.quizlet.quizletandroid.ui.usersettings.adapters.c cVar = changeProfileImageFragment.u;
                if (cVar != null) {
                    ArrayList arrayList = cVar.b;
                    arrayList.clear();
                    arrayList.addAll(it2);
                    String str3 = (String) ((com.quizlet.quizletandroid.ui.usersettings.viewmodels.c) cVar.c.t.getValue()).c.a(DBUserFields.Names.PROFILE_IMAGE_ID);
                    if (str3 == null) {
                        str3 = "";
                    }
                    if (!TextUtils.isEmpty(str3)) {
                        while (true) {
                            if (i < arrayList.size()) {
                                if (str3.equals(((ProfileImage) arrayList.get(i)).getId())) {
                                    int size = cVar.a.size() + i;
                                    ChangeProfileImageFragment changeProfileImageFragment2 = cVar.c;
                                    boolean zY = changeProfileImageFragment2.Y();
                                    boolean z = changeProfileImageFragment2.requireArguments().getBoolean("ARG_ALLOW_CUSTOM_IMAGES");
                                    cVar.d = (z ? 1 : 0) + (zY ? 1 : 0) + size;
                                } else {
                                    i++;
                                }
                            }
                        }
                    }
                    cVar.f();
                    cVar.notifyDataSetChanged();
                }
                break;
            default:
                com.quizlet.quizletandroid.ui.usersettings.data.a aVar = (com.quizlet.quizletandroid.ui.usersettings.data.a) obj;
                String str4 = ChangeProfileImageFragment.w;
                changeProfileImageFragment.V(aVar.a, aVar.b);
                break;
        }
        return Unit.a;
    }
}
