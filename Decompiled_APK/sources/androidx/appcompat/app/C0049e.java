package androidx.appcompat.app;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3768y4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3776z4;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.appcompat.app.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0049e extends ArrayAdapter {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0049e(Context context, int i, int i2, Object[] objArr) {
        super(context, i, i2, objArr);
        this.a = 0;
    }

    @Override // android.widget.ArrayAdapter, android.widget.Adapter
    public long getItemId(int i) {
        switch (this.a) {
            case 0:
                return i;
            default:
                return super.getItemId(i);
        }
    }

    @Override // android.widget.ArrayAdapter, android.widget.Adapter
    public View getView(int i, View layout, ViewGroup parent) {
        switch (this.a) {
            case 1:
                Intrinsics.checkNotNullParameter(parent, "parent");
                String str = (String) getItem(i);
                boolean z = i == 0;
                ArrayList arrayList = com.perimeterx.mobile_sdk.doctor_app.ui.h.a;
                boolean z2 = i == AbstractC3768y4.b().size() - 1;
                if (layout == null) {
                    if (z) {
                        layout = LayoutInflater.from(getContext()).inflate(R.layout.view_px_doctor_instructions_header, parent, false);
                        if (layout == null) {
                            Intrinsics.m("layout");
                            throw null;
                        }
                        ((TextView) layout.findViewById(R.id.instructions_header_title_label)).setText("How does it work?");
                        Button button = (Button) layout.findViewById(R.id.instructions_header_skip_button);
                        button.setText("Skip");
                        button.setOnClickListener(new com.braze.ui.inappmessage.f(7));
                        button.setOnTouchListener(new com.braze.ui.a(9));
                    } else if (z2) {
                        layout = LayoutInflater.from(getContext()).inflate(R.layout.view_px_doctor_instructions_footer, parent, false);
                        if (layout == null) {
                            Intrinsics.m("layout");
                            throw null;
                        }
                        ImageView imageView = (ImageView) layout.findViewById(R.id.instructions_footer_image_view);
                        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
                        Intrinsics.d(fVar);
                        imageView.setImageBitmap(((C1721Kc) fVar.f).a("noun_refresh_smartphone"));
                        Button button2 = (Button) layout.findViewById(R.id.instructions_footer_let_start_button);
                        Resources resources = layout.getResources();
                        androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                        Intrinsics.d(fVar2);
                        button2.setBackground(new BitmapDrawable(resources, ((C1721Kc) fVar2.f).a("rectangle_full_regular")));
                        button2.setText("Let’s start");
                        button2.setOnClickListener(new com.braze.ui.inappmessage.f(8));
                        button2.setOnTouchListener(new com.braze.ui.a(10));
                    } else {
                        layout = LayoutInflater.from(getContext()).inflate(R.layout.view_px_doctor_row_item, parent, false);
                        if (layout == null) {
                            Intrinsics.m("layout");
                            throw null;
                        }
                        AbstractC3776z4.b(layout);
                    }
                }
                if (!z && !z2) {
                    Intrinsics.checkNotNullParameter(layout, "layout");
                    ((TextView) layout.findViewById(R.id.row_item_number_text_view)).setText(String.valueOf(i));
                    ((TextView) layout.findViewById(R.id.row_item_content_text_view)).setText(str);
                }
                return layout;
            case 2:
                Intrinsics.checkNotNullParameter(parent, "parent");
                String str2 = (String) getItem(i);
                if (layout == null) {
                    layout = LayoutInflater.from(getContext()).inflate(R.layout.view_px_doctor_row_item, parent, false);
                    if (layout == null) {
                        Intrinsics.m("layout");
                        throw null;
                    }
                    AbstractC3776z4.b(layout);
                }
                Intrinsics.checkNotNullParameter(layout, "layout");
                ((TextView) layout.findViewById(R.id.row_item_number_text_view)).setText(String.valueOf(i + 1));
                ((TextView) layout.findViewById(R.id.row_item_content_text_view)).setText(str2);
                return layout;
            default:
                return super.getView(i, layout, parent);
        }
    }

    @Override // android.widget.BaseAdapter, android.widget.Adapter
    public boolean hasStableIds() {
        switch (this.a) {
            case 0:
                return true;
            default:
                return super.hasStableIds();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0049e(Context context, int i, List list, int i2) {
        super(context, i, list);
        this.a = i2;
    }
}
