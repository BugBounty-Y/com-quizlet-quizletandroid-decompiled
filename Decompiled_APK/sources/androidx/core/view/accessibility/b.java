package androidx.core.view.accessibility;

import android.view.accessibility.AccessibilityManager;
import android.widget.AutoCompleteTextView;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3472i4;
import com.google.android.material.search.SearchBar;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class b implements AccessibilityManager.TouchExplorationStateChangeListener {
    public final com.google.android.material.search.a a;

    public b(com.google.android.material.search.a aVar) {
        this.a = aVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof b) {
            return this.a.equals(((b) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // android.view.accessibility.AccessibilityManager.TouchExplorationStateChangeListener
    public final void onTouchExplorationStateChanged(boolean z) {
        com.google.android.material.search.a aVar = this.a;
        switch (aVar.a) {
            case 0:
                int i = SearchBar.w1;
                ((SearchBar) aVar.b).setFocusableInTouchMode(z);
                break;
            default:
                com.google.android.material.textfield.i iVar = (com.google.android.material.textfield.i) aVar.b;
                AutoCompleteTextView autoCompleteTextView = iVar.h;
                if (autoCompleteTextView != null && !AbstractC3472i4.a(autoCompleteTextView)) {
                    int i2 = z ? 2 : 1;
                    WeakHashMap weakHashMap = V.a;
                    iVar.d.setImportantForAccessibility(i2);
                    break;
                }
                break;
        }
    }
}
