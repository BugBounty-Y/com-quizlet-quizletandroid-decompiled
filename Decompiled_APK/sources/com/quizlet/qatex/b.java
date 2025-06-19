package com.quizlet.qatex;

import android.content.Context;
import android.content.res.TypedArray;
import android.view.MotionEvent;
import android.webkit.WebView;
import androidx.compose.animation.d0;
import androidx.work.impl.model.v;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.u;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class b extends WebView {
    public String a;
    public int b;
    public float c;
    public boolean d;
    public boolean e;
    public v f;

    static {
        Intrinsics.checkNotNullExpressionValue(b.class.getSimpleName(), "getSimpleName(...)");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public b(@NotNull Context context) {
        this(context, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final void a() throws IOException {
        String formula = this.a;
        if (formula != null) {
            float f = this.c;
            int i = this.b;
            boolean z = this.d;
            Intrinsics.checkNotNullParameter(formula, "formula");
            Context context = getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(formula, "formula");
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(context.getAssets().open("katex/qatex.html")));
            StringBuilder sb = new StringBuilder();
            while (true) {
                String line = bufferedReader.readLine();
                if (line == null) {
                    break;
                }
                sb.append(line);
                sb.append("\n");
            }
            String string = sb.toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            String strO = D.o(D.o(D.o(string, "{textSize}", String.valueOf(f), false), "{textColor}", d0.s(new Object[]{Integer.valueOf(i & 16777215)}, 1, "#%06X", "format(...)"), false), "{katexText}", formula, false);
            String str = z ? " markdown-result" : null;
            if (str == null) {
                str = "";
            }
            String strO2 = D.o(strO, "{resultClass}", str, false);
            u uVar = com.quizlet.themes.extensions.a.a;
            Intrinsics.checkNotNullParameter(context, "<this>");
            context.getTheme().resolveAttribute(R.attr.IsNightTheme, com.quizlet.themes.extensions.a.b(), true);
            String str2 = com.quizlet.themes.extensions.a.b().data != 0 ? "theme-night" : null;
            loadDataWithBaseURL(null, D.o(strO2, "{nightTheme}", str2 != null ? str2 : "", false), "text/html", "utf-8", "about:blank");
        }
    }

    public final float b(float f) {
        if (f > DefinitionKt.NO_Float_VALUE) {
            return f / getResources().getDisplayMetrics().scaledDensity;
        }
        return 16.0f;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchTouchEvent(MotionEvent motionEvent) {
        if (this.e) {
            return super.dispatchTouchEvent(motionEvent);
        }
        return false;
    }

    public final boolean getShouldDispatchTouchEvent() {
        return this.e;
    }

    public final String getText() {
        return this.a;
    }

    public final int getTextColor() {
        return this.b;
    }

    public final float getTextSize() {
        return this.c;
    }

    public final void setShouldDispatchTouchEvent(boolean z) {
        this.e = z;
    }

    public final void setText(@NotNull String text) throws IOException {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
        a();
    }

    public final void setTextColor(int i) throws IOException {
        this.b = i;
        a();
    }

    public final void setTextSizePx(float f) throws IOException {
        this.c = b(f);
        a();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Context context, int i) throws IOException {
        super(context, null, 0);
        Intrinsics.checkNotNullParameter(context, "context");
        this.b = com.quizlet.themes.extensions.a.a(context, R.attr.SysColorTextPrimary);
        this.c = 16.0f;
        setLayerType(2, null);
        getSettings().setAllowFileAccess(true);
        getSettings().setJavaScriptEnabled(true);
        getSettings().setCacheMode(1);
        getSettings().setDisplayZoomControls(false);
        getSettings().setBuiltInZoomControls(false);
        getSettings().setSupportZoom(false);
        getSettings().setUseWideViewPort(false);
        setBackgroundColor(0);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(null, d.a, 0, 0);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        try {
            this.b = com.quizlet.themes.extensions.a.a(context, typedArrayObtainStyledAttributes.getColor(2, com.quizlet.themes.extensions.a.a(context, R.attr.textColor)));
            this.c = b(typedArrayObtainStyledAttributes.getDimension(0, -1.0f));
            String string = typedArrayObtainStyledAttributes.getString(1);
            if (string != null) {
                this.a = string;
            }
        } finally {
            a();
            typedArrayObtainStyledAttributes.recycle();
        }
    }
}
