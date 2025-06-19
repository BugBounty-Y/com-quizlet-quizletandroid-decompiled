
// Do not edit directly
// See https://github.com/quizlet/quizlet-design-tokens for code generation


package com.quizlet.ui.resources.designsystem.generated;

import androidx.compose.ui.graphics.Color

interface SysColor {
    
    /** Color of Light: `gray800` / Dark: `gray200` */
    val sysColorTextPrimary: Color
    
    /** Color of Light: `gray600` / Dark: `gray400` */
    val sysColorTextSecondary: Color
    
    /** Color of Light: `gray100` / Dark: `twilight900` */
    val sysColorSurface: Color
    
    /** Color of Light: `gray300` / Dark: `gray800` */
    val sysColorBorder: Color
    
    /** Color of Light: `scrim300` / Dark: `scrim200` */
    val sysColorScrim: Color
    
    /** Color of Light: `twilight200` / Dark: `twilight400` */
    val sysColorTextBackgroundSelected: Color
    
    /** Color of Light: `gray300` / Dark: `gray700` */
    val sysColorCardBorder: Color
    
    /** Color of Light: `mint600` / Dark: `mint400` */
    val sysColorSuccess: Color
    
    /** Color of Light: `cherry500` / Dark: `cherry300` */
    val sysColorError: Color
    
    /** Color of Light: `gray400` / Dark: `gray600` */
    val sysColorDisabled: Color
    
    /** Color of Light: `twilight300` / Dark: `twilight300` */
    val sysColorHighlight: Color
    
    /** Color of Light: `sunset400` / Dark: `sunset400` */
    val sysColorUpgrade: Color
    
    /** Color of Light: `gray100none` / Dark: `twilight900none` */
    val sysColorSurfaceNone: Color
    
    /** Color of Light: `gray100` / Dark: `gray700` */
    val sysColorCard: Color
    
    /** Color of Light: `gray300` / Dark: `gray800` */
    val sysColorDivider: Color
    
    /** Color of Light: `gray200` / Dark: `twilight900` */
    val sysColorBackground: Color

    object Light : SysColor {
        override val sysColorTextPrimary: Color = RefColor.refColorGray800
        override val sysColorTextSecondary: Color = RefColor.refColorGray600
        override val sysColorSurface: Color = RefColor.refColorGray100
        override val sysColorBorder: Color = RefColor.refColorGray300
        override val sysColorScrim: Color = RefColor.refColorScrim300
        override val sysColorTextBackgroundSelected: Color = RefColor.refColorTwilight200
        override val sysColorCardBorder: Color = RefColor.refColorGray300
        override val sysColorSuccess: Color = RefColor.refColorMint600
        override val sysColorError: Color = RefColor.refColorCherry500
        override val sysColorDisabled: Color = RefColor.refColorGray400
        override val sysColorHighlight: Color = RefColor.refColorTwilight300
        override val sysColorUpgrade: Color = RefColor.refColorSunset400
        override val sysColorSurfaceNone: Color = RefColor.refColorGray100None
        override val sysColorCard: Color = RefColor.refColorGray100
        override val sysColorDivider: Color = RefColor.refColorGray300
        override val sysColorBackground: Color = RefColor.refColorGray200
    }

    object Dark : SysColor {
        override val sysColorTextPrimary: Color = RefColor.refColorGray200
        override val sysColorTextSecondary: Color = RefColor.refColorGray400
        override val sysColorSurface: Color = RefColor.refColorTwilight900
        override val sysColorBorder: Color = RefColor.refColorGray800
        override val sysColorScrim: Color = RefColor.refColorScrim200
        override val sysColorTextBackgroundSelected: Color = RefColor.refColorTwilight400
        override val sysColorCardBorder: Color = RefColor.refColorGray700
        override val sysColorSuccess: Color = RefColor.refColorMint400
        override val sysColorError: Color = RefColor.refColorCherry300
        override val sysColorDisabled: Color = RefColor.refColorGray600
        override val sysColorHighlight: Color = RefColor.refColorTwilight300
        override val sysColorUpgrade: Color = RefColor.refColorSunset400
        override val sysColorSurfaceNone: Color = RefColor.refColorTwilight900None
        override val sysColorCard: Color = RefColor.refColorGray700
        override val sysColorDivider: Color = RefColor.refColorGray800
        override val sysColorBackground: Color = RefColor.refColorTwilight900
    }
}
