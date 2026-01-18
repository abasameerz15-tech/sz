local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local UIS = game:GetService("UserInputService")
local TweenService = game:GetService("TweenService")

local Player = Players.LocalPlayer
local PlayerGui = Player:WaitForChild("PlayerGui")

-- [ تنظيف الواجهة القديمة لتجنب التكرار ]
if PlayerGui:FindFirstChild("Abbas_Elite_Final") then
    PlayerGui.Abbas_Elite_Final:Destroy()
end

-- ===== واجهة المستخدم (GUI) =====
local Gui = Instance.new("ScreenGui", PlayerGui)
Gui.Name = "Abbas_Elite_Final"
Gui.ResetOnSpawn = false

-- [ الزر العائم ]
local MainToggle = Instance.new("TextButton", Gui)
MainToggle.Size = UDim2.new(0, 55, 0, 55)
MainToggle.Position = UDim2.new(0, 20, 0, 200)
MainToggle.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
MainToggle.Text = "A"
MainToggle.TextColor3 = Color3.fromRGB(0, 255, 255)
MainToggle.Font = Enum.Font.GothamBold
MainToggle.TextSize = 25
MainToggle.Draggable = true
Instance.new("UICorner", MainToggle).CornerRadius = UDim.new(1, 0)
Instance.new("UIStroke", MainToggle).Color = Color3.fromRGB(0, 255, 255)

-- [ القائمة الرئيسية ]
local MainFrame = Instance.new("Frame", Gui)
MainFrame.Size = UDim2.new(0, 360, 0, 420)
MainFrame.Position = UDim2.new(0.5, 0, 0.5, 0)
MainFrame.AnchorPoint = Vector2.new(0.5, 0.5)
MainFrame.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
MainFrame.Visible = false
Instance.new("UICorner", MainFrame)
Instance.new("UIStroke", MainFrame).Color = Color3.fromRGB(40, 40, 40)

local Content = Instance.new("ScrollingFrame", MainFrame)
Content.Size = UDim2.new(1, -20, 1, -70)
Content.Position = UDim2.new(0, 10, 0, 60)
Content.BackgroundTransparency = 1
Content.CanvasSize = UDim2.new(0, 0, 1.5, 0)
Content.ScrollBarThickness = 2
Instance.new("UIListLayout", Content).Padding = UDim.new(0, 12)

local Title = Instance.new("TextLabel", MainFrame)
Title.Size = UDim2.new(1, 0, 0, 50)
Title.Text = "المطور | عمك عبيس"
Title.TextColor3 = Color3.fromRGB(0, 200, 255)
Title.Font = Enum.Font.GothamBold
Title.TextSize = 20
Title.BackgroundTransparency = 1

-- [ دالة إنشاء الخيارات ]
local function CreateOption(text, hasSlider, max, default)
    local active = false
    local val = default or 0

    local Item = Instance.new("Frame", Content)
    Item.Size = UDim2.new(1, -5, 0, hasSlider and 65 or 45)
    Item.BackgroundColor3 = Color3.fromRGB(22, 22, 22)
    Instance.new("UICorner", Item)

    local Label = Instance.new("TextLabel", Item)
    Label.Text = text .. (hasSlider and " : " .. val or "")
    Label.Size = UDim2.new(0, 200, 0, 30)
    Label.Position = UDim2.new(0, 12, 0, 5)
    Label.TextColor3 = Color3.new(1,1,1)
    Label.Font = Enum.Font.GothamMedium
    Label.TextSize = 14
    Label.TextXAlignment = Enum.TextXAlignment.Left
    Label.BackgroundTransparency = 1

    local Switch = Instance.new("TextButton", Item)
    Switch.Size = UDim2.new(0, 42, 0, 22)
    Switch.Position = UDim2.new(1, -52, 0, 10)
    Switch.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
    Switch.Text = ""
    Instance.new("UICorner", Switch).CornerRadius = UDim.new(1, 0)

    local Circle = Instance.new("Frame", Switch)
    Circle.Size = UDim2.new(0, 18, 0, 18)
    Circle.Position = UDim2.new(0, 2, 0.5, 0)
    Circle.AnchorPoint = Vector2.new(0, 0.5)
    Circle.BackgroundColor3 = Color3.new(1,1,1)
    Instance.new("UICorner", Circle).CornerRadius = UDim.new(1, 0)

    Switch.MouseButton1Click:Connect(function()
        active = not active
        TweenService:Create(Circle, TweenInfo.new(0.2), {Position = active and UDim2.new(1, -20, 0.5, 0) or UDim2.new(0, 2, 0.5, 0)}):Play()
        TweenService:Create(Switch, TweenInfo.new(0.2), {BackgroundColor3 = active and Color3.fromRGB(0, 200, 255) or Color3.fromRGB(40, 40, 40)}):Play()
    end)

    if hasSlider then
        local SliderBG = Instance.new("Frame", Item)
        SliderBG.Size = UDim2.new(1, -24, 0, 6)
        SliderBG.Position = UDim2.new(0, 12, 0, 50)
        SliderBG.BackgroundColor3 = Color3.fromRGB(50, 50, 50)
        Instance.new("UICorner", SliderBG)

        local Fill = Instance.new("Frame", SliderBG)
        Fill.Size = UDim2.new(val/max, 0, 1, 0)
        Fill.BackgroundColor3 = Color3.fromRGB(0, 200, 255)
        Instance.new("UICorner", Fill)

        local Trigger = Instance.new("TextButton", SliderBG)
        Trigger.Size = UDim2.new(1, 0, 1, 0)
        Trigger.BackgroundTransparency = 1
        Trigger.Text = ""

        local dragging = false
        local function UpdateSlider()
            local mouseX = UIS:GetMouseLocation().X
            local relativeX = mouseX - SliderBG.AbsolutePosition.X
            local percent = math.clamp(relativeX / SliderBG.AbsoluteSize.X, 0, 1)
            val = math.floor(percent * max)
            Fill.Size = UDim2.new(percent, 0, 1, 0)
            Label.Text = text .. " : " .. val
        end

        Trigger.MouseButton1Down:Connect(function() dragging = true; UpdateSlider() end)
        UIS.InputChanged:Connect(function(input)
            if dragging and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
                UpdateSlider()
            end
        end)
        UIS.InputEnded:Connect(function(input)
            if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then dragging = false end
        end)
    end

    return function() return active, val end
end

-- [ المتحكمات ]
local SpeedControl = CreateOption("تفعيل السرعة", true, 300, 16)
local JumpControl = CreateOption("تفعيل القفز", true, 500, 50)
local InfJumpControl = CreateOption("قفز لانهائي", false)
local ESPControl = CreateOption("كشف لاعبين (ESP)", false)

-- [ المنطق الرئيسي - تم إصلاح مشكلة عدم الرجوع للطبيعي ]
RunService.RenderStepped:Connect(function()
    if Player.Character then
        local hum = Player.Character:FindFirstChild("Humanoid")
        if hum then
            -- 1. التعامل مع السرعة
            local isSpeedOn, speedValue = SpeedControl()
            if isSpeedOn then
                hum.WalkSpeed = speedValue
            else
                hum.WalkSpeed = 16 -- يرجع للطبيعي عند الإغلاق
            end

            -- 2. التعامل مع القفز
            local isJumpOn, jumpValue = JumpControl()
            if isJumpOn then
                hum.UseJumpPower = true 
                hum.JumpPower = jumpValue
            else
                hum.JumpPower = 50 -- يرجع للطبيعي عند الإغلاق
            end
        end
    end

    -- 3. التعامل مع الـ ESP
    local isESPOn = ESPControl()
    if isESPOn then
        for _, p in pairs(Players:GetPlayers()) do
            if p ~= Player and p.Character then
                local char = p.Character
                local hrp = char:FindFirstChild("HumanoidRootPart")
                local hum = char:FindFirstChild("Humanoid")
                if hrp and hum and hum.Health > 0 then
                    local hl = char:FindFirstChild("AbbasHL") or Instance.new("Highlight", char)
                    hl.Name = "AbbasHL"; hl.FillColor = Color3.fromRGB(255, 0, 0); hl.OutlineColor = Color3.fromRGB(255,255,255); hl.Enabled = true
                    
                    local head = char:FindFirstChild("Head")
                    if head then
                        local tag = head:FindFirstChild("AbbasTag") or Instance.new("BillboardGui", head)
                        tag.Name = "AbbasTag"; tag.AlwaysOnTop = true; tag.Size = UDim2.new(0, 100, 0, 50); tag.ExtentsOffset = Vector3.new(0, 3, 0); tag.Enabled = true
                        local lbl = tag:FindFirstChild("L") or Instance.new("TextLabel", tag)
                        lbl.Name = "L"; lbl.Size = UDim2.new(1,0,1,0); lbl.BackgroundTransparency = 1; lbl.TextColor3 = Color3.fromRGB(0, 170, 255); lbl.Font = Enum.Font.GothamBold; lbl.TextSize = 14; lbl.TextStrokeTransparency = 0
                        lbl.Text = p.DisplayName .. " [".. math.floor(hum.Health) .."]"
                    end
                end
            end
        end
    else
        for _, p in pairs(Players:GetPlayers()) do
            if p.Character then
                if p.Character:FindFirstChild("AbbasHL") then p.Character.AbbasHL:Destroy() end
                if p.Character:FindFirstChild("Head") and p.Character.Head:FindFirstChild("AbbasTag") then p.Character.Head.AbbasTag:Destroy() end
            end
        end
    end
end)

-- [ قفز لانهائي ]
UIS.JumpRequest:Connect(function()
    local isInfJumpOn = InfJumpControl()
    if isInfJumpOn then
        local hum = Player.Character and Player.Character:FindFirstChild("Humanoid")
        if hum then hum:ChangeState(Enum.HumanoidStateType.Jumping) end
    end
end)

-- [ فتح وإغلاق القائمة ]
MainToggle.MouseButton1Click:Connect(function()
    if MainFrame.Visible then
        local t = TweenService:Create(MainFrame, TweenInfo.new(0.3), {Size = UDim2.new(0,0,0,0)})
        t:Play()
        t.Completed:Connect(function() MainFrame.Visible = false end)
    else
        MainFrame.Visible = true
        MainFrame.Size = UDim2.new(0,0,0,0)
        TweenService:Create(MainFrame, TweenInfo.new(0.4, Enum.EasingStyle.Back), {Size = UDim2.new(0, 360, 0, 420)}):Play()
    end
end)