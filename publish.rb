File.readlines('versions').each do |line|
    tagged = line.split(":")
    basename = tagged[0]
    oldname = basename + "-latest"
    newname = basename + "-" + tagged[1].strip!

    `cat build/#{basename}.html | sed -e 's/#{oldname}/#{newname}/' > build/#{newname}.html`
    `cat build/#{basename}.txt | sed -e 's/#{oldname}/#{newname}/' > build/#{newname}.txt`
end
