package com.onetrust.otpublishers.headless.UI.adapter;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.compose.ui.text.C0981a;
import androidx.recyclerview.widget.C1364f;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.V;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3681n4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3689o4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3697p4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.quizlet.quizletandroid.R;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class r extends V {
    public final com.onetrust.otpublishers.headless.UI.DataModels.i c;
    public final OTConfiguration d;
    public final String e;
    public final String f;
    public final String g;
    public final C0981a h;
    public final androidx.credentials.playservices.controllers.BeginSignIn.c i;
    public LayoutInflater j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(com.onetrust.otpublishers.headless.UI.DataModels.i sdkListData, OTConfiguration oTConfiguration, String str, String str2, String str3, C0981a onItemCheckedChange, androidx.credentials.playservices.controllers.BeginSignIn.c isAlwaysActiveGroup) {
        super(new s(0));
        Intrinsics.checkNotNullParameter(sdkListData, "sdkListData");
        Intrinsics.checkNotNullParameter(onItemCheckedChange, "onItemCheckedChange");
        Intrinsics.checkNotNullParameter(isAlwaysActiveGroup, "isAlwaysActiveGroup");
        this.c = sdkListData;
        this.d = oTConfiguration;
        this.e = str;
        this.f = str2;
        this.g = str3;
        this.h = onItemCheckedChange;
        this.i = isAlwaysActiveGroup;
    }

    @Override // androidx.recyclerview.widget.V, androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return ((C1364f) this.b).f.size() + 1;
    }

    @Override // androidx.recyclerview.widget.V, androidx.recyclerview.widget.AbstractC1361d0
    public final void onAttachedToRecyclerView(RecyclerView recyclerView) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        super.onAttachedToRecyclerView(recyclerView);
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(recyclerView.getContext());
        Intrinsics.checkNotNullExpressionValue(layoutInflaterFrom, "from(recyclerView.context)");
        this.j = layoutInflaterFrom;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) throws Resources.NotFoundException, NumberFormatException {
        int i2;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        String str;
        q holder = (q) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        List currentList = ((C1364f) this.b).f;
        Intrinsics.checkNotNullExpressionValue(currentList, "currentList");
        com.onetrust.otpublishers.headless.UI.DataModels.g gVar = (com.onetrust.otpublishers.headless.UI.DataModels.g) CollectionsKt.O(i, currentList);
        boolean z2 = i == getItemCount() - 1;
        com.onetrust.otpublishers.headless.databinding.e eVar = holder.a;
        RelativeLayout itemLayout = (RelativeLayout) eVar.g;
        Intrinsics.checkNotNullExpressionValue(itemLayout, "itemLayout");
        itemLayout.setVisibility(!z2 ? 0 : 8);
        TextView viewPoweredByLogo = eVar.i;
        Intrinsics.checkNotNullExpressionValue(viewPoweredByLogo, "viewPoweredByLogo");
        viewPoweredByLogo.setVisibility(z2 ? 0 : 8);
        SwitchCompat switchButton = (SwitchCompat) eVar.c;
        View view3 = eVar.e;
        String str2 = "";
        com.onetrust.otpublishers.headless.UI.DataModels.i iVar = holder.b;
        if (z2 || gVar == null) {
            Intrinsics.checkNotNullExpressionValue(switchButton, "switchButton");
            switchButton.setVisibility(!z2 ? 0 : 8);
            Intrinsics.checkNotNullExpressionValue(view3, "view3");
            view3.setVisibility(!z2 ? 0 : 8);
            com.onetrust.otpublishers.headless.UI.UIProperty.e eVar2 = iVar.p;
            if (eVar2 == null || !eVar2.i) {
                Intrinsics.checkNotNullExpressionValue(viewPoweredByLogo, "");
                viewPoweredByLogo.setVisibility(8);
                return;
            }
            androidx.navigation.internal.m mVar = eVar2.l;
            Intrinsics.checkNotNullExpressionValue(mVar, "sdkListData.otPCUIProper…leDescriptionTextProperty");
            viewPoweredByLogo.setTextColor(Color.parseColor((String) mVar.b));
            Intrinsics.checkNotNullExpressionValue(viewPoweredByLogo, "");
            AbstractC3689o4.g(viewPoweredByLogo, (String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d);
            com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
            Intrinsics.checkNotNullExpressionValue(kVar, "descriptionTextProperty.fontProperty");
            AbstractC3689o4.c(viewPoweredByLogo, kVar, holder.c);
            viewPoweredByLogo.setTextAlignment(P.k(viewPoweredByLogo.getContext()) ? 6 : 4);
            return;
        }
        TextView textView = (TextView) eVar.h;
        textView.setText(gVar.b);
        androidx.navigation.internal.m mVar2 = iVar.k;
        Intrinsics.checkNotNullExpressionValue(textView, "");
        AbstractC3689o4.a(textView, mVar2, null, holder.c, false, 2);
        TextView textView2 = eVar.f;
        Intrinsics.checkNotNullExpressionValue(textView2, "");
        String str3 = gVar.c;
        if (str3 == null || str3.length() == 0 || !iVar.a || "null".equals(str3)) {
            i2 = 8;
        } else {
            AbstractC3689o4.e(textView2, str3);
            i2 = 0;
        }
        textView2.setVisibility(i2);
        AbstractC3689o4.a(textView2, iVar.l, null, holder.c, false, 2);
        String str4 = null;
        switchButton.setOnCheckedChangeListener(null);
        switchButton.setContentDescription(iVar.j);
        switchButton.setOnCheckedChangeListener(new p(0, holder, gVar));
        textView.setLabelFor(R.id.switchButton);
        Intrinsics.checkNotNullExpressionValue(view3, "view3");
        AbstractC3697p4.d(view3, iVar.f);
        Intrinsics.checkNotNullExpressionValue(switchButton, "switchButton");
        switchButton.setVisibility(0);
        boolean z3 = Boolean.parseBoolean(holder.d);
        TextView alwaysActiveTextSdk = eVar.d;
        if (!z3) {
            Intrinsics.checkNotNullExpressionValue(switchButton, "switchButton");
            switchButton.setVisibility(8);
            Intrinsics.checkNotNullExpressionValue(alwaysActiveTextSdk, "alwaysActiveTextSdk");
            alwaysActiveTextSdk.setVisibility(8);
            return;
        }
        Context context = ((RelativeLayout) eVar.b).getContext();
        new JSONObject();
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        String str5 = gVar.a;
        String string = sharedPreferences.getString("OTT_INTERNAL_SDK_GROUP_MAP", "");
        if (string.isEmpty()) {
            OTLogger.c("SdkListHelper", 3, "Empty sdkMap found");
        } else {
            try {
                JSONObject jSONObject = new JSONObject(string);
                Iterator<String> itKeys = jSONObject.keys();
                while (itKeys.hasNext()) {
                    String next = itKeys.next();
                    if (jSONObject.get(next).toString().contains(str5)) {
                        str2 = next;
                    }
                }
            } catch (JSONException e) {
                Z.p("Error while fetching groupId by sdkId : ", e, "SdkListHelper", 6);
            }
            str4 = str2;
        }
        if (str4 == null) {
            return;
        }
        Intrinsics.checkNotNullExpressionValue(str4, "SdkListHelper(root.conte…d(item.id) ?: return@with");
        if (((Boolean) holder.h.invoke(str4)).booleanValue()) {
            Intrinsics.checkNotNullExpressionValue(switchButton, "switchButton");
            switchButton.setVisibility(8);
            Intrinsics.checkNotNullExpressionValue(alwaysActiveTextSdk, "alwaysActiveTextSdk");
            alwaysActiveTextSdk.setVisibility(0);
            alwaysActiveTextSdk.setText(holder.e);
            Intrinsics.checkNotNullExpressionValue(alwaysActiveTextSdk, "alwaysActiveTextSdk");
            AbstractC3689o4.a(alwaysActiveTextSdk, iVar.k, null, holder.c, false, 2);
            String str6 = holder.f;
            if (str6 == null || str6.length() == 0) {
                return;
            }
            alwaysActiveTextSdk.setTextColor(Color.parseColor(str6));
            return;
        }
        Intrinsics.checkNotNullExpressionValue(alwaysActiveTextSdk, "alwaysActiveTextSdk");
        alwaysActiveTextSdk.setVisibility(8);
        int iOrdinal = gVar.d.ordinal();
        if (iOrdinal == 0) {
            switchButton.setChecked(true);
            Intrinsics.checkNotNullExpressionValue(switchButton, "switchButton");
            str = iVar.g;
        } else {
            if (iOrdinal != 1) {
                if (iOrdinal != 2) {
                    return;
                }
                Intrinsics.checkNotNullExpressionValue(switchButton, "switchButton");
                switchButton.setVisibility(8);
                return;
            }
            switchButton.setChecked(false);
            Intrinsics.checkNotNullExpressionValue(switchButton, "switchButton");
            str = iVar.h;
        }
        AbstractC3681n4.a(switchButton, iVar.i, str);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        LayoutInflater layoutInflater = this.j;
        if (layoutInflater == null) {
            Intrinsics.m("inflater");
            throw null;
        }
        View viewInflate = layoutInflater.inflate(R.layout.ot_sdk_list_item, parent, false);
        int i2 = R.id.alwaysActiveTextSdk;
        TextView textView = (TextView) AbstractC3375o2.c(R.id.alwaysActiveTextSdk, viewInflate);
        if (textView != null) {
            i2 = R.id.item_layout;
            RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.item_layout, viewInflate);
            if (relativeLayout != null) {
                i2 = R.id.ot_sdk_list_user_choice;
                if (((FrameLayout) AbstractC3375o2.c(R.id.ot_sdk_list_user_choice, viewInflate)) != null) {
                    i2 = R.id.sdk_description;
                    TextView textView2 = (TextView) AbstractC3375o2.c(R.id.sdk_description, viewInflate);
                    if (textView2 != null) {
                        RelativeLayout relativeLayout2 = (RelativeLayout) viewInflate;
                        i2 = R.id.sdk_name;
                        TextView textView3 = (TextView) AbstractC3375o2.c(R.id.sdk_name, viewInflate);
                        if (textView3 != null) {
                            i2 = R.id.switchButton;
                            SwitchCompat switchCompat = (SwitchCompat) AbstractC3375o2.c(R.id.switchButton, viewInflate);
                            if (switchCompat != null) {
                                i2 = R.id.view3;
                                View viewC = AbstractC3375o2.c(R.id.view3, viewInflate);
                                if (viewC != null) {
                                    i2 = R.id.view_powered_by_logo;
                                    TextView textView4 = (TextView) AbstractC3375o2.c(R.id.view_powered_by_logo, viewInflate);
                                    if (textView4 != null) {
                                        com.onetrust.otpublishers.headless.databinding.e eVar = new com.onetrust.otpublishers.headless.databinding.e(relativeLayout2, textView, relativeLayout, textView2, textView3, switchCompat, viewC, textView4);
                                        Intrinsics.checkNotNullExpressionValue(eVar, "inflate(inflater, parent, false)");
                                        return new q(eVar, this.c, this.d, this.e, this.f, this.g, this.h, this.i);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i2)));
    }
}
