package com.google.android.gms.oss.licenses;

import android.content.Context;
import android.content.res.Resources;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;
import androidx.work.impl.model.v;
import com.google.android.gms.internal.oss_licenses.zze;
import java.util.ArrayList;
import org.xmlpull.v1.XmlPullParser;

/* loaded from: classes2.dex */
public final class e extends ArrayAdapter {
    public final /* synthetic */ OssLicensesMenuActivity a;

    /* JADX WARN: Illegal instructions before constructor call */
    public e(OssLicensesMenuActivity ossLicensesMenuActivity, Context context) {
        this.a = ossLicensesMenuActivity;
        v vVar = ossLicensesMenuActivity.f;
        int identifier = ((Resources) vVar.b).getIdentifier("libraries_social_licenses_license", "layout", (String) vVar.c);
        v vVar2 = ossLicensesMenuActivity.f;
        super(context, identifier, ((Resources) vVar2.b).getIdentifier("license", "id", (String) vVar2.c), new ArrayList());
    }

    @Override // android.widget.ArrayAdapter, android.widget.Adapter
    public final View getView(int i, View view, ViewGroup viewGroup) {
        OssLicensesMenuActivity ossLicensesMenuActivity = this.a;
        if (view == null) {
            LayoutInflater layoutInflater = ossLicensesMenuActivity.getLayoutInflater();
            v vVar = ossLicensesMenuActivity.f;
            Resources resources = (Resources) vVar.b;
            view = layoutInflater.inflate((XmlPullParser) resources.getXml(resources.getIdentifier("libraries_social_licenses_license", "layout", (String) vVar.c)), viewGroup, false);
        }
        v vVar2 = ossLicensesMenuActivity.f;
        ((TextView) view.findViewById(((Resources) vVar2.b).getIdentifier("license", "id", (String) vVar2.c))).setText(((zze) getItem(i)).a);
        return view;
    }
}
