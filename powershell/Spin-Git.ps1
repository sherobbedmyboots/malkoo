# create a new repository on the command line

echo "# malkoo" >> README.md
git init
git add README.md
git commit -m "first commit"
git remote add origin git@github.com:<user>/<repo>.git
git push -u origin master

# Push an existing repository

git remote add origin git@github.com:<user>/<repo>.git
git push -u origin master