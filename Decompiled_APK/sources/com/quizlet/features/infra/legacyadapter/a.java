package com.quizlet.features.infra.legacyadapter;

import android.view.View;
import android.widget.Toast;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3116c6;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.group.classuser.ClassUserListFragment;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(Object obj, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        switch (this.a) {
            case 0:
                e eVar = (e) this.c;
                int i = this.b;
                DBModel dBModelD = eVar.d(i);
                if (dBModelD != null) {
                    eVar.a.d(view, i, dBModelD);
                    break;
                }
                break;
            default:
                ClassUserListFragment classUserListFragment = (ClassUserListFragment) this.c;
                classUserListFragment.getClass();
                int i2 = this.b;
                if (i2 == -3) {
                    DBGroupMembership dBGroupMembership = new DBGroupMembership();
                    classUserListFragment.D = dBGroupMembership;
                    dBGroupMembership.setClassId(classUserListFragment.F.g);
                    classUserListFragment.D.setUserId(classUserListFragment.A.getPersonId());
                    classUserListFragment.D.setLevel(0);
                    classUserListFragment.y.a(classUserListFragment.D);
                    Toast.makeText(classUserListFragment.getActivity(), classUserListFragment.getString(R.string.join_request_received), 0).show();
                    classUserListFragment.C.notifyDataSetChanged();
                    break;
                } else if (i2 != -2 && i2 != -1) {
                    if (i2 == 0) {
                        DBGroupMembership dBGroupMembership2 = classUserListFragment.D;
                        if (dBGroupMembership2 != null) {
                            dBGroupMembership2.setDeleted(true);
                            classUserListFragment.y.a(classUserListFragment.D);
                        }
                        classUserListFragment.D = null;
                        Toast.makeText(classUserListFragment.getActivity(), classUserListFragment.getString(R.string.request_cancelled), 0).show();
                        classUserListFragment.C.notifyDataSetChanged();
                        break;
                    }
                } else {
                    AbstractC3116c6.h(R.string.admin_must_add_to_class, classUserListFragment.getFragmentManager());
                    break;
                }
                break;
        }
    }
}
